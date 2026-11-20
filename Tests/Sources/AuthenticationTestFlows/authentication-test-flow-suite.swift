import TestFlows

enum AuthenticationFlowSuite:
    TestFlowRegistry
{
    static let title = "Auth"

    static let flows: [TestFlow] = [
        authorizationFlow,
        sessionLifetimeFlow,
        capabilityFlow,
        identityIdentifierFlow,
        stringIdentifierFlow,
        authenticationContextFlow,
        passwordFlow,
        accessTokenFlow,
        accessTokenConstraintsFlow,
        serverAccessTokenProtectionFlow,
    ]
}
