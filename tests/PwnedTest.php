<?php

namespace Square1\Pwned\Tests;

use Square1\Pwned\Pwned;
use PHPUnit_Framework_TestCase as TestCase;

class ExampleTest extends TestCase
{
    /**
     * Test setup
     */
    public function setUp()
    {
        parent::setUp();

        $this->pwned = new Pwned();
    }


    /**
     * Test default config population on creation
     */
    public function test_default_config_population_on_create()
    {
        $p = new Pwned();

        $this->assertTrue(!empty($p->getConfig()));
    }


    /**
     * Test config population via constructor
     */
    public function test_config_population_on_create()
    {
        $endpoint = 'http://mytest.domain';
        $pwned = new Pwned(['endpoint' => $endpoint]);

        $this->assertEquals(
            $endpoint,
            $pwned->getConfig()['endpoint']
        );
    }


    /**
     * Test that setting an approved config value works
     */
    public function test_updating_config_value()
    {
        $endpoint = 'http://mytest.domain';
        $config = [
            'endpoint' => $endpoint
        ];
        $this->pwned->setConfig($config);
        $updated = $this->pwned->getConfig();
        $this->assertEquals(
            $endpoint,
            $updated['endpoint']
        );
    }


    /**
     * Test that we can't set a config value for an unknown key
     */
    public function test_updating_config_value_with_unknown_key()
    {
        $config = $this->pwned->getConfig();

        $bad_value_config = ['unknown_field' => 'foo'];
        $this->pwned->setConfig($bad_value_config);

        $this->assertSame(
            $config,
            $this->pwned->getConfig()
        );
    }


    /**
     * Test that password hashing and splitting is working correctly
     */
    public function test_password_hash_and_split()
    {
        $password = 'password1234';
        $expected_range = 'E6B6A';
        $expected_selector = 'FBD6D76BB5D2041542D7D2E3FAC5BB05593';
        list($range, $selector) = $this->pwned->split($password);

        $this->assertEquals(
            $expected_range,
            $range
        );
        $this->assertEquals(
            $expected_selector,
            $selector
        );
    }


    /**
     * Test api response formatting is split into key => count arrays
     */
    public function test_format_api_response()
    {
        $input = "abcd1234abcd1234abcd1234abcd1234:11\nefgh5678efgh5678efgh5678efgh5678:9";
        $expected = [
            "abcd1234abcd1234abcd1234abcd1234" => '11',
            "efgh5678efgh5678efgh5678efgh5678" => '9'
        ];

        $this->assertEquals(
            $expected,
            $this->pwned->formatApiResponse($input)
        );
    }


    /**
     * Test api response when given empty input
     */
    public function test_format_api_response_with_empty_input()
    {
        $this->assertEquals(
            [],
            $this->pwned->formatApiResponse("")
        );
    }
}
