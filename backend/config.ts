import ThirdPartyEmailPassword from "supertokens-node/recipe/thirdpartyemailpassword";
import Passwordless from "supertokens-node/recipe/passwordless";
import Session from "supertokens-node/recipe/session";
import { TypeInput } from "supertokens-node/types";
import Dashboard from "supertokens-node/recipe/dashboard";
import MultiFactorAuth from "supertokens-node/recipe/multifactorauth";
import AccountLinking from "supertokens-node/recipe/accountlinking";
import EmailVerification from "supertokens-node/recipe/emailverification";
import { createHash } from "crypto"
import axios from "axios";
import { Castle } from '@castleio/sdk';
import { APIError, InvalidRequestTokenError } from '@castleio/sdk';
import { BaseRequest } from "supertokens-node/lib/build/framework/request";

export const castle = new Castle({ apiSecret: "Hp3AnQYkn571fXu1GBVA3xeay2TWz2ez" });

export function getApiDomain() {
    const apiPort = process.env.REACT_APP_API_PORT || 3001;
    const apiUrl = process.env.REACT_APP_API_URL || `http://localhost:${apiPort}`;
    return apiUrl;
}

export function getWebsiteDomain() {
    const websitePort = process.env.REACT_APP_WEBSITE_PORT || 3000;
    const websiteUrl = process.env.REACT_APP_WEBSITE_URL || `http://localhost:${websitePort}`;
    return websiteUrl;
}

async function isBreachedPassword(password: string) {
    // send first 5 characters to pwnedpasswords API
    // if response contains the rest of the hash,
    // then password is breached
    let shasum = createHash('sha1');
    shasum.update(password);
    password = shasum.digest('hex');
    let response = await new Promise<boolean>((resolve, reject) => {
        axios.get("https://api.pwnedpasswords.com/range/" + password.substring(0, 5))
            .then((response) => {
                let hashSuffix = password.substring(5).toUpperCase();
                let hashes = response.data.split("\n");
                for (let i = 0; i < hashes.length; i++) {
                    if (hashes[i].split(":")[0] === hashSuffix) {
                        resolve(true);
                    }
                }
                resolve(false);
            })
            .catch((err) => {
                reject(err);
            })
    });
    return response;
}

async function makeCastleCall(email: string | undefined, req: BaseRequest, type: "$login" | "$registration") {
    let jsonObject = await req.getJSONBody();
    return await castle.filter({
        request_token: jsonObject["castleToken"],
        context: getHeadersAndIpFromExpressLikeRequest(req.original),
        type,
        status: '$attempted',
        params: {
            email,
        },
    });
}

function getHeadersAndIpFromExpressLikeRequest(req: Request): {
    headers: { [key: string]: string },
    ip: string
} {
    let headers: { [key: string]: string } = {};
    for (let key of Object.keys(req.headers)) {
        headers[key] = (req as any).headers[key]!;
    }
    return {
        headers,
        ip: (req as any).headers['x-forwarded-for'] || "127.0.0.1"
    }

}

export const SuperTokensConfig: TypeInput = {
    supertokens: {
        // this is the location of the SuperTokens core.
        connectionURI: "https://st-dev-9356eb90-f6fd-11ee-a7a1-057a50fdd964.aws.supertokens.io",
        apiKey: "vNGqkPgjFhAzmA1OKAZP4kVSwh"
    },
    appInfo: {
        appName: "SuperTokens Demo App",
        apiDomain: getApiDomain(),
        websiteDomain: getWebsiteDomain(),
    },
    // recipeList contains all the modules that you want to
    // use from SuperTokens. See the full list here: https://supertokens.com/docs/guides
    recipeList: [
        ThirdPartyEmailPassword.init({
            override: {
                functions: (oI) => {
                    return {
                        ...oI,
                        updateEmailOrPassword: async (input) => {
                            if (input.password !== undefined && await isBreachedPassword(input.password)) {
                                throw new Error("Password breached");
                            }
                            return await oI.updateEmailOrPassword(input);
                        },
                        emailPasswordSignUp: async (input) => {
                            if (await isBreachedPassword(input.password)) {
                                throw new Error("Password breached");
                            }
                            return await oI.emailPasswordSignUp(input);
                        },
                        emailPasswordSignIn: async (input) => {
                            let response = await oI.emailPasswordSignIn(input);
                            if (response.status === "OK") {
                                if (await isBreachedPassword(input.password)) {
                                    throw new Error("Password breached");
                                }
                            }
                            return response;
                        },
                    }
                },
                apis: (oI) => {
                    return {
                        ...oI,
                        passwordResetPOST: async function (input) {
                            try {
                                return await oI.passwordResetPOST!(input);
                            } catch (err: any) {
                                if (err.message === "Password breached") {
                                    return {
                                        status: "GENERAL_ERROR",
                                        message: "Please use another password since this password has been breached"
                                    }
                                }
                                throw err;
                            }
                        },
                        emailPasswordSignInPOST: async (input) => {
                            try {
                                const result: any = await makeCastleCall(input.formFields.find(v => v.id === "email")!.value, input.options.req, "$login");
                                // Handle "deny" actions
                                if (result.policy.action === 'deny') {
                                    return {
                                        status: "GENERAL_ERROR",
                                        message: "Cannot sign in right now."
                                    }
                                }
                            } catch (e) {
                                if (e instanceof InvalidRequestTokenError) {
                                    // Invalid request token is very likely a bad actor bypassing fingerprinting
                                    return {
                                        status: "GENERAL_ERROR",
                                        message: "Cannot sign in right now."
                                    }
                                } else if (e instanceof APIError) {
                                    // Allow attempt. Data missing or invalid, or a server or timeout error
                                }
                            }
                            try {
                                return await oI.emailPasswordSignInPOST!(input);
                            } catch (err: any) {
                                if (err.message === "Password breached") {
                                    return {
                                        status: "GENERAL_ERROR",
                                        message: "Your password has been detected in a breach. Please click on the forgot password button below."
                                    }
                                }
                                throw err;
                            }
                        },
                        emailPasswordSignUpPOST: async (input) => {
                            try {
                                const result: any = await makeCastleCall(input.formFields.find(v => v.id === "email")!.value, input.options.req, "$registration");
                                // Handle "deny" actions
                                if (result.policy.action === 'deny') {
                                    return {
                                        status: "GENERAL_ERROR",
                                        message: "Cannot sign up right now."
                                    }
                                }
                            } catch (e) {
                                if (e instanceof InvalidRequestTokenError) {
                                    // Invalid request token is very likely a bad actor bypassing fingerprinting
                                    return {
                                        status: "GENERAL_ERROR",
                                        message: "Cannot sign up right now."
                                    }
                                } else if (e instanceof APIError) {
                                    // Allow attempt. Data missing or invalid, or a server or timeout error
                                }
                            }
                            try {
                                input.userContext.isSignUp = true;
                                return await oI.emailPasswordSignUpPOST!(input);
                            } catch (err: any) {
                                if (err.message === "Password breached") {
                                    return {
                                        status: "GENERAL_ERROR",
                                        message: "Please use another password since this password has been breached"
                                    }
                                }
                                throw err;
                            }
                        },
                        thirdPartySignInUpPOST: async (input) => {
                            try {
                                const result: any = await makeCastleCall(undefined, input.options.req, "$login");
                                // Handle "deny" actions
                                if (result.policy.action === 'deny') {
                                    return {
                                        status: "GENERAL_ERROR",
                                        message: "Cannot login right now."
                                    }
                                }
                            } catch (e) {
                                if (e instanceof InvalidRequestTokenError) {
                                    // Invalid request token is very likely a bad actor bypassing fingerprinting
                                    return {
                                        status: "GENERAL_ERROR",
                                        message: "Cannot login right now."
                                    }
                                } else if (e instanceof APIError) {
                                    // Allow attempt. Data missing or invalid, or a server or timeout error
                                }
                            }
                            input.userContext.isThirdPartyLogin = true;
                            return oI.thirdPartySignInUpPOST!(input);
                        },
                    }
                }
            },
            providers: [
                // We have provided you with development keys which you can use for testing.
                // IMPORTANT: Please replace them with your own OAuth keys for production use.
                {
                    config: {
                        thirdPartyId: "google",
                        clients: [
                            {
                                clientId: "1060725074195-kmeum4crr01uirfl2op9kd5acmi9jutn.apps.googleusercontent.com",
                                clientSecret: "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",
                            },
                        ],
                    },
                },
                {
                    config: {
                        thirdPartyId: "apple",
                        clients: [
                            {
                                clientId: "4398792-io.supertokens.example.service",
                                additionalConfig: {
                                    keyId: "7M48Y4RYDL",
                                    privateKey:
                                        "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgu8gXs+XYkqXD6Ala9Sf/iJXzhbwcoG5dMh1OonpdJUmgCgYIKoZIzj0DAQehRANCAASfrvlFbFCYqn3I2zeknYXLwtH30JuOKestDbSfZYxZNMqhF/OzdZFTV0zc5u5s3eN+oCWbnvl0hM+9IW0UlkdA\n-----END PRIVATE KEY-----",
                                    teamId: "YWQCXGJRJL",
                                },
                            },
                        ],
                    },
                },
            ],
        }),
        EmailVerification.init({
            mode: "OPTIONAL"
        }),
        Passwordless.init({
            contactMethod: "EMAIL",
            flowType: "USER_INPUT_CODE",
        }),
        AccountLinking.init({
            shouldDoAutomaticAccountLinking: async () => ({
                shouldAutomaticallyLink: true,
                shouldRequireVerification: true,
            }),
        }),
        MultiFactorAuth.init({
            firstFactors: ["thirdparty", "emailpassword"],
            override: {
                functions: (oI) => ({
                    ...oI,
                    getMFARequirementsForAuth: (input) => {
                        if (input.userContext.isSignUp === true || input.userContext.isThirdPartyLogin === true) {
                            return [];
                        }
                        return [
                            MultiFactorAuth.FactorIds.OTP_EMAIL,
                        ]
                    },
                }),
            },
        }),
        Session.init(),
        Dashboard.init(),
    ],
};
