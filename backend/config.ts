import ThirdPartyEmailPassword from "supertokens-node/recipe/thirdpartyemailpassword";
import Passwordless from "supertokens-node/recipe/passwordless";
import Session from "supertokens-node/recipe/session";
import { TypeInput } from "supertokens-node/types";
import Dashboard from "supertokens-node/recipe/dashboard";
import MultiFactorAuth from "supertokens-node/recipe/multifactorauth";
import AccountLinking from "supertokens-node/recipe/accountlinking";
import EmailVerification from "supertokens-node/recipe/emailverification";

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
                        thirdPartyId: "github",
                        clients: [
                            {
                                clientId: "467101b197249757c71f",
                                clientSecret: "e97051221f4b6426e8fe8d51486396703012f5bd",
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
                {
                    config: {
                        thirdPartyId: "twitter",
                        clients: [
                            {
                                clientId: "4398792-WXpqVXRiazdRMGNJdEZIa3RVQXc6MTpjaQ",
                                clientSecret: "BivMbtwmcygbRLNQ0zk45yxvW246tnYnTFFq-LH39NwZMxFpdC",
                            },
                        ],
                    },
                },
            ],
        }),
        EmailVerification.init({
            mode: "REQUIRED"
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
                    getMFARequirementsForAuth: () => [
                        MultiFactorAuth.FactorIds.OTP_EMAIL,
                    ],
                }),
            },
        }),
        Session.init(),
        Dashboard.init(),
    ],
};
