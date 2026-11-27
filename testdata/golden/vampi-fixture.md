**authzcov:** 5 of 42 required authorization checks covered (11.9%), 37 gaps.

| Required | Covered | Waived | Gaps | Unmatched requests | Ambiguous matches |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 42 | 5 | 0 | 37 | 0 | 0 |

### Top gaps

| Endpoint | Missing test |
| --- | --- |
| DELETE /users/v1/{username} | another user with the same role |
| GET /books/v1/{book\_title} | another user with the same role |
| GET /users/v1/{username} | another user with the same role |
| PUT /users/v1/{username}/email | another user with the same role |
| PUT /users/v1/{username}/password | another user with the same role |
| GET / | a lower role |
| GET /books/v1 | a lower role |
| GET /createdb | a lower role |
| GET /me | a lower role |
| GET /users/v1 | a lower role |
| GET /users/v1/\_debug | a lower role |
| POST /books/v1 | a lower role |
| POST /users/v1/login | a lower role |
| POST /users/v1/register | a lower role |
| DELETE /users/v1/{username} | an anonymous caller |
| GET / | an anonymous caller |
| GET /books/v1 | an anonymous caller |
| GET /createdb | an anonymous caller |
| GET /me | an anonymous caller |
| GET /users/v1 | an anonymous caller |

<details>
<summary>17 more gaps</summary>

| Endpoint | Missing test |
| --- | --- |
| GET /users/v1/\_debug | an anonymous caller |
| GET /users/v1/{username} | an anonymous caller |
| POST /books/v1 | an anonymous caller |
| POST /users/v1/login | an anonymous caller |
| POST /users/v1/register | an anonymous caller |
| PUT /users/v1/{username}/email | an anonymous caller |
| PUT /users/v1/{username}/password | an anonymous caller |
| DELETE /users/v1/{username} | the owner |
| GET / | the owner |
| GET /books/v1 | the owner |
| GET /createdb | the owner |
| GET /users/v1 | the owner |
| GET /users/v1/\_debug | the owner |
| POST /users/v1/login | the owner |
| POST /users/v1/register | the owner |
| PUT /users/v1/{username}/email | the owner |
| PUT /users/v1/{username}/password | the owner |

</details>

<sub>authzcov dev · authzcov\.coverage/v1</sub>
