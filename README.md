# CAFFEINE MANAGER API
> The caffeine intake tracker API

Implemented using Flask, SQLAlchemy and SQLite3

### Defined API endpoints

##### Creating resources
 - `/user/request` - methods `POST`
    - Create user
    - Expects JSON object with fields `login`, `email` (both must be unique) and `password`
    - Returns `201` and JSON object containing `id` - unique id assigned to the user
 - `/machine` - methods `POST`
   - Create machine
   - Expects JSON object with fields `name` and `caffeine`(indicating caffeine amount per serving)
   - Returns `201` and JSON object containing `id` - unique id assigned to the machine
##### Listing resources
 - `/users` - methods `GET`
   - List all users in the database
   - Returns `200` and JSON object with array `users`, where each user has `login`, `email` and `id`
 - `/machines` - methods `GET`
   - List all machines in the database
   - Returns `200` and JSON object with array `machines`, where each machine has `name`, `id` and `caffeine`
##### Registering transactions
 - `/coffee/buy/<user_id>/<machine_id>` - methods `GET, PUT`
   - Registers coffee served by `machine_id` to `user_id`
   - On method `GET` registers drink served at the current time, on method `PUT` expects JSON object with `timestamp` - ISO8061 timestamp of serving.
   - Returns `201`
 ##### Reading stats
   - `/stats/coffee` - methods `GET`
     - List all drinks purchased globally
     - Returns `200` and a JSON object with array `sold_coffee_global`, 
       where each coffee served has `time`, `sold_by`, `sold_by_id` and `caffeine`
   - `/stats/coffee/machine/<machine_id>` - methods `GET`
     - List all drinks served by `machine_id`
     - Returns `200` and JSON object with `machine_id`, `machine_name`, `caffeine` 
     and array `sold_drinks`, where each drink has `sold_on` timestamp
   - `/stats/coffee/user/<user_id>` - methods `GET`
     - List all drinks served to `user_id`
     - Requires Authentication by the same user as `user_id`!
     [see User authentication](#user-authentication)
     - Returns `200` and a JSON object with `user_id`, `user`(user's login), `user_email`
     and an array `drinks_bought`, where each drink has `time`, `sold by`, `sold_by_id` and `caffeine`
##### User authentication
   - `/user/login` - methods `GET`
     - Get authentication token for a user.
     - Expects http request with `Basic auth` authorization header with user's login and password.
     - Returns a JSON object with `user_id` and `token`

Endpoints, that require authentication, expect this token to be present in the `x-access-token` header of the http request.
Else they return `401` forbidden.

##### Epilogue
This is just a basic abstract APi, I might add more functionality in the future, one thing that comes to mind is the 
ability to delete users, machines will stay non-deletable for sure.
