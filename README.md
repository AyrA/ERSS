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
- Doesn't needs any write access to your system
- Doesn't needs a database
- Doesn't needs session support
- Doesn't needs read access to the tor configuration
- People can block as well as unblock their IP address
- Only accepts block/unblock requests for IP address the request is made for
- Stateless; there's no chance for it to be out of sync with your real ExitPolicy setting
- Blocked ranges persist across Tor restarts (will update the actual configuration)

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
This is usually done by resetting the permissions/owner of the file to whatever it would have inherited if it were created by the www user.

### Manual Configuration

**CAUTION**: The manual configuration is not validated. Be sure to only enter valid data.

If you want to create a configuration by hand, you can do so.
Create a JSON object with these keys:

- **ip** (string): The IP of the Tor instance. Usually 127.0.0.1
- **port** (number): The TCP port number of the ControlPort directive. Usually 9051
- **password** (string): Password for the ControlPort. See "Custom Password" section below
- **hmac** (string): This should be any long string of random characters. By default it's 32 random bytes as HEX encoded
- **showlist** (bool): If enabled, the full black list (IP address entries only) is shown in the portal to everyone
- **captcha-private** (string): reCAPTCHA private key. Use `null` instead of a string to disable
- **captcha-public** (string): reCAPTCHA public key. Use `null` instead of a string to disable

Be **very** careful to not mix up the public and private keys for the captcha.
They look similar in the first half.

Save the serialized JSON with the prefix `<?php //` as `config.php` (unless you changed the `CONFIG_FILE` constant).
Be sure to serialize the JSON into a single line.
If you did this properly, accessing config.php should just yield a blank page.

### Custom Password

You can use the `hashPassword` function in `include.php` to create the hash for Tor if you want to create the portal configuration manually.
If you use the portal itself to make a configuration,
you can see and example password and config file lines below the form.
You can use the provided randomly generated password or you can type your own and submit the form.
After submitting the form, the password lines will be updated to show the hash for your currently chosen password.

## reCAPTCHA

The portal supports reCAPTCHA. Using it is optional.
You can get a token from [Google](https://www.google.com/recaptcha) for free.
Using reCAPTCHA means that the token form requires JavaScript to work.
Otherwise this solution is completely free of dependencies.