# ERSS

Exit Relay Self Service

This web portal allows people to blacklist the IP address of their service
if they believe that malicious traffic is coming from your exit relay.

It stops manual intervention by the relay operator for when people want their address (un-)blocked

## Features

- Easy to use
- Fully automatic management of the ExitPolicy configuration
- Supports IPv6
- Supports reCAPTCHA
- Doesn't needs JavaScript if the captcha is not used
- Doesn't needs any write access to your system
- Doesn't needs a database
- Doesn't needs session support
- Doesn't needs read access to the tor configuration
- People can block as well as unblock their IP address
- Only accepts block/unblock requests for IP address the request is made for
- Stateless; there's no chance for it to be out of sync with your real ExitPolicy setting
- Blocked ranges persist across Tor restarts (will update the actual configuration)
- Without the captcha, works in most text based web browsers, which makes it suitable to be used from the command line

## Requirements

- Webserver with PHP support (for example Apache, Nginx or IIS)
- PHP Version 5.3 or newer
- Tor in relay mode

It's recommended that the Tor configuration is writable by the Tor process (not the web server or PHP).
If it's not, the configuration can't be saved and any policy change made by the portal is lost during restarts.

## Limitations

This utility works only on individual IP addresses.

- You can't block selected ports of an address, it always uses `*` for the port segment.
- It silently converts existing `IP:Port` entries into `IP:*` the first time you block an address with it
- It ignores (but preserves) CIDR notation

The portal will preserve port-only rules that are in the format `*:Number`.

The portal doesn't checks if a proposed IP entry is included in an existing CIDR entry.
This can lead to unnecessary "reject" lines but will not harm operation of the portal or Tor.

### Tor configuration

The portal will propose example configuration settings during the setup phase.
It usually boils down to two lines you have to make sure are present in your Tor configuration:

- `ControlPort 9051`: This enables control connections on port 9051. The number can vary
- `HashedControlPassword 16:...`: This contains the hashed password for authentication

Both lines can exist multiple times.
Multiple `ControlPort` lines indicate that Tor will listen on multiple ports.
Multiple `HashedControlPassword` lines indicate that Tor will accept multiple passwords.

Note: All passwords are valid for all listeners.

Don't forget to restart Tor if you change the configuration.
On linux you can also sometimes get away with sending a HUP signal
if you no longer feel validated by the Tor community by resetting the uptime counter of your relay.

## Installation

Copy `reject.php` and `include.php` to a web server directory of your choice,
then access `reject.php` in your browser and fill in the requested values.

### Tor Front Page

Tor supports delivering a custom HTML file via the `DirPortFrontPage` directive (optional).
It's recommended that you use this feature when running an exit relay.
The Tor project provides an example file in their repository.
You can use this file and replace/extend the contact section with a link to the self service portal.

This repository provides a very simple `DirPortFrontPage.html` file for your convenience.
Please edit the file and fill in the relay id and your public IP address or domain name
where indicated by HTML comments.

### Optional Customization

The file `include.php` can be customized by changing a few constants (usually not necessary):

- **CONFIG_FILE**: Change the name and location of the configuration
- **TOKEN_EXPIRATION**: How long a token is valid (in minutes)
- **PASSWORD_CHARSET**: Password charset for the password generator

### No Write Access

This portal strictly speaking doesn't needs write access at any time.
If it's unable to save the configuration during the installation period,
it will print an error message that contains the exact line
so you can save it manually without compromising server security with write permissions.

Just be sure that the webserver user has read access if you create the file using root/Administrator access.

### Manual Configuration

**CAUTION**: The manual configuration is not validated. Be sure to only enter valid data.

If you want to create a configuration by hand, you can do so.
Create a JSON object with these keys:

- **ip** (string): The IP of the Tor instance. Usually 127.0.0.1
- **port** (number): The TCP port number of the ControlPort directive. Usually 9051
- **password** (string): Password for the ControlPort. See "Custom Password" section below
- **hmac** (string): This should be any long string of random characters. By default it's 32 random bytes as HEX encoded
- **showlist** (bool): If enabled, the full list of IP addresses is shown in the portal to everyone
- **captcha-private** (string): reCAPTCHA private key. Use `null` instead of a string to disable
- **captcha-public** (string): reCAPTCHA public key. Use `null` instead of a string to disable

Be **very** careful to not mix up the public and private keys for the captcha.
They look similar in the first half.

Save the serialized JSON with the prefix `<?php //` as `config.php` (unless you changed the `CONFIG_FILE` constant).
Be sure to serialize the JSON into a single line.
If you did this properly, `config.php` is a single line with a PHP start tag and a commented JSON

### Custom Password

You can use the `hashPassword` function in `include.php` to create the hash for Tor if you want to create the portal configuration manually.
If you use the portal itself to make a configuration,
you can see an example password and config file lines below the form.
You can use the provided randomly generated password or you can type your own and submit the form.
After submitting the form, the password lines will be updated to show the hash for your currently chosen password.

## reCAPTCHA

The portal supports reCAPTCHA. Using it is optional.
You can get a token from [Google](https://www.google.com/recaptcha) for free.
Using reCAPTCHA means that the token form requires JavaScript to work.
Otherwise this solution is completely free of dependencies.
The reCAPTCHA framework is only loaded from google servers if you supply the keys for it.

## About Tokens

This portal creates tokens using a hmac function.
The tokens allow it to function in a fully readonly environment.
It doesn't requires any temporary files or session mechanism at all.

The token is made up of the current system time, requested action and the IP address of the caller.

When a request to block or unblock is made, the supplied token is validated against the IP address and the supplied values.
This is done to prove a few things:

- The token is for the IP that makes the current request
- The supplied timestamp is still valid
- The token is for the requested action

If the token is validated successfully, the requested action is taken


### Avoiding Abuse

The requested token action is only taken if it makes sense to do it.
It will not try to add duplicates or remove entries that are not there.

Somebody might still try to send a massive number of add/remove requests to bog down your Tor client.

Here are a few methods on how to avoid this:

#### Global Lock

This is simple, just open `reject.php` using `fopen()`, then `flock()` the file pointer (and don't forget to unlock at the end).
This means your page will now only process one request at a time.
This can be a bit dangerous if somebody sends a very slow request (see "Slow Loris Attack")

#### IP Lock

This is almost as simple as the global lock, but it requires write access somewhere on the server.
The temp directory is fine for this.

1. Calculate the sha1 hash of the client IP address
2. Open `/tmp/$hash` for writing instead of `reject.php`, then proceed with the locking.
3. Optionally, delete the file from the temp directory once you're done with it.

You can unlink the file while it's open on Linux but not Windows.
Be careful if you plan on unlinking the file while it's still open.

#### Server Limits

This file will not cause the browser to load a single resource from your server.
This means that you can get away with limiting an IP address to a single connection
if you don't relly use the web server for something else.

#### Reduce token lifetime

10 Minutes is a generous amount of time to connect to a server to make it issue a POST request.
You can probably get away with a single minute. This means an IP needs to get a token 10 times as often.

You can edit `reject.php` to provide a cURL command instead of text instructions.

#### Captcha

The captcha puts a dampener on automation.
In your reCAPTCHA settings you can crank up the difficulty too if you want.
Higher difficulty means that people are less likely to pass the captcha just with the checkbox.

#### Tarpitting

In combination with the locking,
adding a 5 second delay before you take an action greatly reduces the number of requests a client can make.
