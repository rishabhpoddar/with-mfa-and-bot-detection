import ThirdPartyEmailPassword, {
    Google,
    Apple,
} from "supertokens-auth-react/recipe/thirdpartyemailpassword";
import { ThirdPartyEmailPasswordPreBuiltUI } from "supertokens-auth-react/recipe/thirdpartyemailpassword/prebuiltui";
import Passwordless from "supertokens-auth-react/recipe/passwordless";
import { PasswordlessPreBuiltUI } from "supertokens-auth-react/recipe/passwordless/prebuiltui";
import MultiFactorAuth from "supertokens-auth-react/recipe/multifactorauth";
import { MultiFactorAuthPreBuiltUI } from "supertokens-auth-react/recipe/multifactorauth/prebuiltui";
import Session from "supertokens-auth-react/recipe/session";
import Castle from '@castleio/castle-js'

const castle = Castle.configure({ pk: 'pk_pm1G7ivoFQA7HDA9TLjqa1JywNeDYJrN' });

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

export const SuperTokensConfig = {
    appInfo: {
        appName: "SuperTokens Demo App",
        apiDomain: getApiDomain(),
        websiteDomain: getWebsiteDomain(),
    },
    // recipeList contains all the modules that you want to
    // use from SuperTokens. See the full list here: https://supertokens.com/docs/guides
    recipeList: [
        ThirdPartyEmailPassword.init({
            preAPIHook: async (context) => {
                if (context.action === "EMAIL_PASSWORD_SIGN_IN" ||
                    context.action === "EMAIL_PASSWORD_SIGN_UP" ||
                    context.action === "THIRD_PARTY_SIGN_IN_UP") {
                    let requestInit = context.requestInit;
                    const body = requestInit.body;
                    if (typeof body === "string") {
                        let castleToken = await new Promise<string | undefined>((resolve) => {
                            castle.createRequestToken().then((token) => {
                                resolve(token)
                            }, () => {
                                resolve(undefined)
                            })
                        });
                        if (castleToken !== undefined) {
                            requestInit.body = JSON.stringify({
                                ...JSON.parse(body),
                                castleToken
                            });
                        }
                    }
                }
                return context;
            },
            signInAndUpFeature: {
                providers: [Google.init(), Apple.init()],
            },
        }),
        Passwordless.init({
            contactMethod: "EMAIL",
        }),
        MultiFactorAuth.init(),
        Session.init(),
    ],
};

export const recipeDetails = {
    docsLink: "https://supertokens.com/docs/mfa/introduction",
};

export const PreBuiltUIList = [
    ThirdPartyEmailPasswordPreBuiltUI,
    PasswordlessPreBuiltUI,
    MultiFactorAuthPreBuiltUI,
];

export const ComponentWrapper = (props: { children: JSX.Element }): JSX.Element => {
    return props.children;
};
