<?php

namespace Square1\Pwned;

use Exception;
use Square1\Pwned\Exception\GeneralException;
use Square1\Pwned\Exception\ConnectionFailedException;

/**
 * Usage:
 *
 * $pwned = new Pwned();
 * // Has password ever been compromised?
 * $compromised = $pwned->hasBeenPwned($password);
 *
 *
 * // Has password appeared in more than 5 compromised datasets?
 * $compromised = $pwned->hasBeenPwned($password, 5);
 *
 *
 * // Don't allow remote server to hang for over 2 seconds
 * try {
 *     $pwned = new Pwned(['remote_processing_timeout' => 2]);
 *     $compromised = $pwned->hasBeenPwned($password);
 * } catch (ConnectionFailedException $e) {
 *     // Connection has timed out..
 * }
 */
class Pwned
{
    /**
     * @var array
     */
    private $config = [];

    /**
     * First N chars of hash supported by range search
     * @var integer
     */
    private $range_size = 5;


    /**
     * Constructor
     *
     * @param array $config Default config overrides
     */
    public function __construct($config = [])
    {
        $config = !empty($config) ? $config : $this->getDefaultConfig();
        $this->setConfig($config);
    }


    /**
     * Get current config options
     *
     * @return array
     */
    public function getConfig()
    {
        return $this->config;
    }


    /**
     * Default configuration options
     *
     * @return array
     */
    public function getDefaultConfig()
    {
        return [
            'endpoint' => 'https://api.pwnedpasswords.com/range/',
            'user_agent' => 'Square1 Pwned PHP package',
            // Initial curl connection limit (0 for off)
            'connection_timeout' => 0,
            // Max time waiting for response after connection (0 for off)
            'remote_processing_timeout' => 0,
            'minimum_occurrences' => 1,
        ];
    }


    /**
     * Is a given password showing in the dataset of pwned passwords?
     * Optional limit on number of times it appears in compromised data. This allows site owners to
     * allow passwords that may only appear once or twice in the data, but block regularly-compromised
     * entries
     *
     * @param string $password
     * @param int    $minimum
     *
     * @return boolean
     */
    public function hasBeenPwned($password, $minimum = null)
    {
        if ($minimum == null) {
            $minimum = $this->config['minimum_occurrences'];
        }
        $count = $this->getCountFromApi($password);
        return $count > $minimum;
    }


    /**
     * Set configuration settings
     *
     * @param array $config Key-value pair of settings
     */
    public function setConfig($config)
    {
        $valid_config = array_intersect_key(
            $config,
            $this->getDefaultConfig()
        );

        $config = array_merge(
            $this->getDefaultConfig(),
            $valid_config
        );

        if (empty($config)) {
            return;
        }

        foreach ($config as $key => $value) {
            $this->config[$key] = $value;
        }
    }


    /**
     * Get the number of times a given password has appeared in breaches
     *
     * @param string $value Password
     *
     * @return integer
     */
    public function getCountFromApi($value)
    {
        // Full-password search is a burden on the remote api, so we do a range search based on the
        // start of the hashed password
        list($range, $selector) = $this->split($value);

        $result = $this->getApiResultsForRange($range);

        if (!array_key_exists($selector, $result)) {
            return 0;
        }

        return $result[$selector];
    }


    /**
     * Make api call for password range
     *
     * @param string $range
     *
     * @return array
     *
     * @throws ConnectionFailedException
     * @throws GeneralException
     */
    public function getApiResultsForRange($range)
    {
        $ch = curl_init($this->config['endpoint'].$range);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, $this->config['user_agent']);

        if (array_key_exists('connection_timeout', $this->config)
            && $this->config['connection_timeout'] > 0) {
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $this->config['connection_timeout']);
        }

        if (array_key_exists('remote_processing_timeout', $this->config)
            && $this->config['remote_processing_timeout'] > 0) {
            curl_setopt($ch, CURLOPT_TIMEOUT, $this->config['remote_processing_timeout']);
        }

        try {
            $results = curl_exec($ch);

            // Connection not finished successfully, throw exception rather than just returning false
            if (false === $results) {
                throw new ConnectionFailedException(
                    'Pwned Password connection failed - '.curl_error($ch).' ('.curl_errno($ch).')'
                );
            }
            curl_close($ch);

        } catch (Exception $e) {
            throw new GeneralException(
                'Pwned Password Validation failed - '.$e->getMessage()
            );
        }

        return $this->formatApiResponse($results);
    }


    /**
     * Format the api response into key-val array for easier selector lookup
     *
     * @param string $input Response from api
     *
     * @return array
     */
    public function formatApiResponse($input)
    {
        $input = trim($input);

        if (empty($input)) {
            return [];
        }

        // Dig through results to get range
        $lines = explode("\n", trim($input));

        if (empty($lines)) {
            return [];
        }

        // Scan it, and change it to SELECTOR => ID format for easier use
        foreach ($lines as $line) {
            list($selector, $count) = explode(":", trim($line));
            $response[$selector] = $count;
        }

        return $response;
    }


    /**
     * Prepare password value for range search by hashing and splitting
     *
     * @param string $value Input password
     *
     * @return array Range and selector prepared for api query
     */
    public function split($value)
    {
        $value = strtoupper(sha1($value));

        return [
            substr($value, 0, $this->range_size),
            substr($value, $this->range_size)
        ];
    }
}