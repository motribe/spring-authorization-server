# Spring Authorization Server with Password Grant

This project is a sample implementation of Spring Authorization Server with Password Grant support.

## Dependencies

This project is built using Gradle and includes the following dependencies:

- Spring Boot
- Spring Security
- Spring Authorization Server

## Getting Started

To get started with this project, follow these steps:

1. Clone the repository to your local machine.
2. Open the project in your preferred IDE.
3. Build the project using Gradle.
4. Run the project using the `bootRun` task.

## Usage

Once the project is running, you can use the following endpoints to interact with the authorization server:

- `/oauth2/token` - This endpoint is used to obtain an access token using the password grant type. You will need to provide a valid username and password in the request body.
- `/oauth2/authorize` - This endpoint is used to initiate the authorization flow. You will need to provide a valid client ID and redirect URI in the request parameters.

## Configuration

This project includes a default configuration for the authorization server. You can customize the configuration by modifying the `application.yml` file.

## License

This project is licensed under the MIT License. See the `LICENSE` file for more information.