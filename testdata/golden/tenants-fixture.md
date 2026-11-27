**authzcov:** 6 of 11 required authorization checks covered (54.5%), 5 gaps.

| Required | Covered | Waived | Gaps | Unmatched requests | Ambiguous matches |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 11 | 6 | 0 | 5 | 0 | 0 |

### Top gaps

| Endpoint | Missing test |
| --- | --- |
| POST /orgs/{orgId}/projects | a user from another tenant |
| GET /orgs/{orgId}/projects | a lower role |
| GET /orgs/{orgId}/projects | an anonymous caller |
| POST /orgs/{orgId}/projects | an anonymous caller |
| GET /orgs/{orgId}/projects | the owner |

<sub>authzcov dev · authzcov\.coverage/v1</sub>
