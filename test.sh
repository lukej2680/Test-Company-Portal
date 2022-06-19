TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTY0NjI1MzA0MSwianRpIjoiNWNlM2ZiNTMtZWEwNS00YzBkLTgzYzQtMGQ3MDg0NTZjZDMwIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6IkRyYWdvbjYiLCJuYmYiOjE2NDYyNTMwNDEsImV4cCI6MTY0NjMzOTQ0MX0.moHvChVN_U5HkZiI3NZxClIuZQkXoBE6LFSSv8VLYj0"
curl -X GET -H 'Accept: application/json' -H "Authorization: Bearer ${TOKEN}" localhost:8080/profile

# Create user 'tester1' with password 'password'
curl -X POST -H "Content-Type: application/json" -d '{"username":"tester1","password":"password","email":"test@gmail.com"}' 127.0.0.1:8080/api/v1/signup
# Returns
{
  "msg": "User created successfully."
}

# Log in with the new credentials
curl -X POST -H "Content-Type: application/json" -d '{"username":"tester1","password":"password"}' 127.0.0.1:8080/api/v1/login
# Returns 
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6dHJ1ZSwiaWF0IjoxNjU1NjQ4MDk1LCJqdGkiOiI0NmI0ZmRhMi0xOGI5LTQ1ZjQtYTI3MC1hMjA2Yjc4ZDZhOTAiLCJ0eXBlIjoiYWNjZXNzIiwic3ViIjoidGVzdGVyMSIsIm5iZiI6MTY1NTY0ODA5NSwiZXhwIjoxNjU1NjUxNjk1LCJhZG1pbiI6ZmFsc2V9.Df1k6Zf9URQGNGeoHs3t_00CDK9bCo98oACGotuAEFM"
}

# Load user profile 
# This route is JWT protected. Need to set Token in header
NEW_TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTY1NTY1MDc1MCwianRpIjoiMWM5Nzg0ZDYtYWZjMC00MDE0LWI1YTctYmYxOGYxNzdjMzdkIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6InRlc3RlcjEiLCJuYmYiOjE2NTU2NTA3NTAsImV4cCI6MTY1NTY1NDM1MCwiYWRtaW4iOmZhbHNlfQ.fS4tU-LC2XAfmdQ-Vv5gN9UhnADgy13dPUT1mewRWZM"
curl -X GET -H 'Content-Type: application/json' -H "Authorization: Bearer ${NEW_TOKEN}" localhost:8080/api/v1/loadUser
# Return
{
  "profile": {
    "email": "test@gmail.com", 
    "username": "tester1"
  }
}

# Log out
# Route is JWT protected, will use same token as before
curl -X DELETE -H 'Content-Type: application/json' -H "Authorization: Bearer ${NEW_TOKEN}" localhost:8080/api/v1/logout
# Return 
{
  "msg": "Token successfully revoked"
}

# Try to load user profile using revoked token
curl -X GET -H 'Content-Type: application/json' -H "Authorization: Bearer ${NEW_TOKEN}" localhost:8080/api/v1/loadUser
# Return
{
  "msg": "Token has been revoked"
}

