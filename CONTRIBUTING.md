This project welcomes contributions and suggestions. Most contributions require you to
agree to a Contributor License Agreement (CLA) declaring that you have the right to,
and actually do, grant us the rights to use your contribution. For details, visit
https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need
to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the
instructions provided by the bot. You will only need to do this once across all repositories using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/)
or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.


## Reporting Issues
Please open a new issue to describe the problem and suggestions to address the problem. You may also open an issue for asking questions and seeking help from the project community.

**_NOTE:_** If your issue is related to a security vulnerability, please follow the guidelines mentioned in the [Security](SECURITY.md) file.

## Branching Guidelines
We have 3 tags associated with the code
1. Main - this is where all the active development happens. New PRs are merged from the feature branches to the **main** branch.
2. Release - this branch tracks the release candidate. Based on the release content, the **release** branch is cutoff from the **main** branch and is subjected to additional testing.
3. Stable - **Release** branch is promoted to a stable tag after testing completes. Please use the **stable** tag for the most stable version of the project.

## Contributing to Source Code
Here are a set of guidelines for contributing code to the project:
1. Please create a separate feature branch forking off from the main branch with your code changes.
2. Please follow the Linux kernel coding style for any code changes - https://www.kernel.org/doc/html/v4.10/process/coding-style.html
**_DISCLAIMER:_** We are working towards aligning the existing code repository to the coding style mentioned above. Therefore, you may observe discrepancy between the existing coding style vs the Linux kernel coding style. Please be assured that we are actively working on fixing this discrepancy in order to make it ready for upstream. However - we expect all new code changes to adhere to the coding style mentioned above.
3. Please submit the PR describing the fix and the tests that were run to validate the fix. The maintainers will get in touch with you wrt your PR. If you dont receive a response within a reasonable time, please feel free to email the maintainers.

## Maintainers
Microsoft Azure Site Recovery Disk Filter Driver for Linux maintainer list is available at [GitHub teams](https://github.com/orgs/microsoft/teams/asrsourceteam/members).
