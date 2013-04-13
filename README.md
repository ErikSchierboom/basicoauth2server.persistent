# Basic OAuth 2.0 server on ASP.NET MVC that stores its tokens in a persistent store

## Introduction
Creating an OAuth 2.0 server is hard. Luckily, the [DotNetOpenAuth](http://www.dotnetopenauth.net/) (DNOA) library takes away a lot of the pain. But still it is quite hard to implement an OAuth 2.0 server using DNOA. Therefore I have created a small ASP.NET MVC 4 website that uses DNOA to function as an OAuth 2.0 server. To be able to test this server, there is also a small console application that connects to the server and requests some tokens. The code has been sprinkled with comments to explain in detail what the application does and why.

## Usage
 1. Clone this project to your development machine
 2. Open the BasicOAuth2Server.Persisent.sln solution file
 3. Build the solution
 4. Run the OAuth2Server website
 5. Use the website's built in test client or run the OAuth2Client application

## License
[Apache License 2.0](License.MD)
