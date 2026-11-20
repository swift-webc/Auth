import TestFlows

@main
enum AuthenticationTestFlowsMain {
    static func main() async {
        await TestFlowCLI.run(
            suite: AuthenticationFlowSuite.self
        )
    }
}
