# Azure Active Directory (AAD) - Offline Authentication

This sample provides a basic design and approach for an application which can go occasionally offline while application still needs to continue execution and perform Authentication (AuthN).

#### Key Objectives
1. Cache and Persist Token for Offline Mode Authentication
2. Extend Validation and Expiration of Token
3. Make cache token temper free using Encryption and Validate with Public Key
4. Refresh Token as Application comes online

#### Pre-Requisite
* .NET Core [Download from <a href="http://dot.net" target="_blank">.NET Core</a>]
* <a href="https://www.visualstudio.com/thank-you-downloading-visual-studio/?sku=Community&rel=15#" target="_blank">Visual Studio Community [2017 Edition]</a> or <a href="https://code.visualstudio.com/?wt.mc_id=vscom_downloads" target="_blank">Visual Studio Code</a>
* Microsoft Azure Subscription (In case if you dont have, sign-up for Free Account <a href="https://azure.microsoft.com/en-in/free/" target="_blank">here</a>)
