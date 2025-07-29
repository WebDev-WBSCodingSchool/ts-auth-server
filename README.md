This is an example for an independent microservice providing JWT tokens for handling authentication and authorization for other services and clients. It will issue access and refresh tokens and share their signing secrets with other back end services using it. Those data services will validate tokens on their own. Also this service will share a Mongo database with said data services for easy user data retrieval.

This auth service provides user registration, login, token refresh and rotation, access token blacklisting, and logout.
