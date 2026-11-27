**authzcov:** 5 of 12 required authorization checks covered (41.7%), 7 gaps.

| Required | Covered | Waived | Gaps | Unmatched requests | Ambiguous matches |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 12 | 5 | 0 | 7 | 0 | 0 |

### Top gaps

| Endpoint | Missing test |
| --- | --- |
| POST /orgs/{orgId}/projects | a user from another tenant |
| GET /orgs/{orgId}/projects | another user with the same role |
| POST /orgs/{orgId}/projects | another user with the same role |
| GET /orgs/{orgId}/projects | an anonymous caller |
| POST /orgs/{orgId}/projects | an anonymous caller |
| GET /orgs/{orgId}/projects | the owner |
| POST /orgs/{orgId}/projects | the owner |

<sub>authzcov dev · authzcov\.coverage/v1</sub>
