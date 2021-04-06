# VulnerabiliTea

VulnerabiliTea is a Free and Open-Source security vulnerability management webapp for penetration testers.

## Features
**Manage all your security vulnerability discoveries in one place**
+ A vast choice of fields, HTML descriptions
+ Attachments
+ Public and private discovery publishing
+ Editing after publishing
+ Activity feed with vote system for public discoveries (WIP)
+ Token-generation based share center for private discoveries
+ User profiles

## Pre-Requisites
+ Node.JS
+ NPM
+ MongoDB

## Installation & Deploying

Use the following command to install the package dependencies

```
npm i
```
Now you have two ways to deploy the webapp:
1. Editing `config.json` manually and starting the webapp with `node app.js`
2. Using environment variables   
If you are using this method you will be required to set the `PORT` and `MONGODB_URI` environment variables before starting. This can be done like so:

    ```bash
    /* Linux */
    MONGODB_URI="mongodb://localhost/VulnerabiliTea" PORT=8080 node app.js
    
    /* Windows (Powershell) */
    $env:MONGODB_URI = "mongodb://localhost/VulnerabiliTea"
    $env:PORT = 8081
    node app.js
    ```

> If you want HTTPS you must also set the `ACME_URI` and `ACME_SERVE` environment variables


## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](https://choosealicense.com/licenses/mit/)