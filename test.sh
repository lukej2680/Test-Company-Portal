TOKEN="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTY0NjI1MzA0MSwianRpIjoiNWNlM2ZiNTMtZWEwNS00YzBkLTgzYzQtMGQ3MDg0NTZjZDMwIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6IkRyYWdvbjYiLCJuYmYiOjE2NDYyNTMwNDEsImV4cCI6MTY0NjMzOTQ0MX0.moHvChVN_U5HkZiI3NZxClIuZQkXoBE6LFSSv8VLYj0"
curl -X GET -H 'Accept: application/json' -H "Authorization: Bearer ${TOKEN}" localhost:8080/profile