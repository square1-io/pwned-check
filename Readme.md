# Pwned Check

PHP utility class to check whether a given password is a known compromised password, using the [Pwned Passwords](https://haveibeenpwned.com/Passwords) service provided by [Troy Hunt](https://www.troyhunt.com/).

## Install

Via Composer

``` bash
$ composer require square1/pwned-check
```

## Usage

``` php
    use Square1\Pwned\Pwned;
    use Square1\Pwned\Exception\ConnectionFailedException;

    $password = 'password1';

    $pwned = new Pwned();
    // Has password ever been compromised?
    $compromised = $pwned->hasBeenPwned($password);
    // (bool) true

    // Has password appeared in more than 5 compromised datasets?
    $compromised = $pwned->hasBeenPwned($password, 5);

    // Don't allow remote server to hang for over 2 seconds
    try {
        $pwned = new Pwned(['remote_processing_timeout' => 2]);
        $compromised = $pwned->hasBeenPwned($password);
    } catch (ConnectionFailedException $e) {
       // Connection has timed out..
    }
```

## Options

A number of constructor options are available to modify the behaviour of the class.

| Option | Default | Comment |
|--------|---------|---------|
| `endpoint` | `https://api.pwnedpasswords.com/range/` | Service endpoint url |
| `user_agent` | `Square1 Pwned PHP package` | User agent to use - api calls without a user agent are rejected |
| `connection_timeout` | `0` | Initial curl connection limit (0 for off). If connection takes longer than X seconds to establish, it's terminated |
| `remote_processing_timeout` | `0` | Number of seconds after which to kill a slow-responding connection (0 for off) |
| `minimum_occurrences` | `1` | Minimum number of times a password needs to appear in breaches before being considered compromised |

## FAQ

### How do you decide if a password is "known compromised"?

The [Pwned Passwords](https://haveibeenpwned.com/Passwords) service provided by [Troy Hunt](https://www.troyhunt.com/) is a great resource that aggregates passwords found in known data breaches. The api allows us to check whether a password has appeared in previous data breaches, and also how frequently it shows up. The frequency allows us to decide how strict we want to be when deciding if a password is to be considered compromised. For example, `abcd1234` may show up 334,000 times in data breaches, while `totallyuniqueandrandompass1234` may only show up once. Depending on your use case, it may be appropriate to only blacklist widely compromised passwords. The frequency count is what allows us to do this.


### Does sending a password to the service not constitute a security risk?

The Pwned password api allows for range queries to be made. This involves hashing the password via this library within your application, and sending a partial section of it to the api. The api returns a set of password hashes (and frequency counts for each). These can then be matched against the full password hash, which never needs to leave the application. Cloudflare worked closely with Troy on the design of this api, and go into a lot more detail on this approach to using k-anonymity in [this blog post](https://blog.cloudflare.com/validating-leaked-passwords-with-k-anonymity/).


### What if the api server is slow to respond? Will my app have problems?

Typical api responses are blazingly-fast - the article [here](https://www.troyhunt.com/i-wanna-go-fast-why-searching-through-500m-pwned-passwords-is-so-quick/) is worth a read. However, it's possible that at some point there'll be a connection issue or some other performance issue with the service. To protect your app in these cases, you can set the `connection_timeout` and `remote_processing_timeout` values. These are the seconds to wait before killing a curl connection and wait time after connection respectively. If the service call is terminated due to one of these timeouts being reached, a `Square1\Pwned\Exception\ConnectionFailedException` will be thrown.


### Are the api results cached?

This code is intended to be framework-agnostic, so caching is left to your application layer.

## Testing

``` bash
$ composer test
```

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
