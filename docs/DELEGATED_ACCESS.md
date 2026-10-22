# Delegated-access references for shared-password debt

Checked against official documentation on 22 October 2026. These references
inform the next debt-flow implementation; they are not claims of automatic
platform integration or completed delegation. Follow each service's own flow,
then record the result. Do not collect client passwords through an intake form.

| Platform scope | Direction | Official reference |
| --- | --- | --- |
| Google Business Profile | Give each person their own Google Account and appropriate profile owner/manager access. This does not cover arbitrary Google services. | [Owners and managers](https://support.google.com/business/answer/3403100?hl=en-GB) |
| LinkedIn Pages | Assign a Page admin role appropriate to the job; personal profiles are separate. | [Page admin permissions](https://www.linkedin.com/help/linkedin/answer/a550647/linkedin-page-admin-roles-permissions) |
| TikTok Business Center | Use partner assignment and account/asset permissions through Business Center. | [Add partners](https://ads.tiktok.com/resources/help/article/invite-partners-into-tiktok-business-center?lang=en) |
| Shopify stores | Use the client's official collaborator/staff access flow with the required store sections. | [Working on client stores](https://help.shopify.com/en/partners/manage-clients-stores/working-on-client-stores) |
| WordPress installations | Use separate site users with suitable roles/capabilities. Custom installations may differ. | [Roles and capabilities](https://wordpress.org/documentation/article/roles-and-capabilities/) |
| GitHub organizations | Assign individual, team or outside-collaborator repository roles. Separate keys/tokens need their own inventory. | [Repository roles](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-repository-roles/repository-roles-for-an-organization) |
| Slack workspaces | Prefer individual identities and appropriate workspace/guest roles; plan availability must be checked by the administrator. No paid upgrade is authorized. | [Role types](https://slack.com/help/articles/360018112273-Types-of-roles-in-Slack) |
| Meta Business Portfolio | The official page could not be inspected without sign-in, so its detailed instructions are not verified here. | [Official help, sign-in required](https://www.facebook.com/business/help/1717412048538897) |

The debt counter must measure reported shared logins still in use, not merely
weak passwords. Rotating a password does not eliminate shared-password debt.
Retiring debt must require explicit confirmation that delegated access works
and the shared login has been retired. User confirmation must be labelled as
such; it is not independent website verification. The existing encrypted
credential-action queue should supply staging/rotation progress rather than
introducing another executor. No passwords or unlock keys belong in debt records.
