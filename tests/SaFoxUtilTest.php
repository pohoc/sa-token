<?php

declare(strict_types=1);

namespace SaToken\Tests;

use PHPUnit\Framework\TestCase;
use SaToken\Util\SaFoxUtil;

class SaFoxUtilTest extends TestCase
{
    // ---- UUID ----

    public function testUuidFormat(): void
    {
        $uuid = SaFoxUtil::uuid();
        $this->assertEquals(36, strlen($uuid));
        $this->assertMatchesRegularExpression(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/',
            $uuid
        );
    }

    public function testUuidUniqueness(): void
    {
        $uuids = [];
        for ($i = 0; $i < 100; $i++) {
            $uuids[SaFoxUtil::uuid()] = true;
        }
        $this->assertCount(100, $uuids);
    }

    // ---- randomString ----

    public function testRandomStringLength(): void
    {
        $this->assertEquals(32, strlen(SaFoxUtil::randomString(32)));
        $this->assertEquals(16, strlen(SaFoxUtil::randomString(16)));
        $this->assertEquals(64, strlen(SaFoxUtil::randomString(64)));
    }

    public function testRandomStringDefaultLength(): void
    {
        $this->assertEquals(32, strlen(SaFoxUtil::randomString()));
    }

    public function testRandomStringCharacters(): void
    {
        $str = SaFoxUtil::randomString(100);
        $this->assertMatchesRegularExpression('/^[a-zA-Z0-9]+$/', $str);
    }

    public function testRandomStringUniqueness(): void
    {
        $strings = [];
        for ($i = 0; $i < 50; $i++) {
            $strings[SaFoxUtil::randomString()] = true;
        }
        $this->assertCount(50, $strings);
    }

    // ---- isEmpty / isNotEmpty ----

    public function testIsEmptyWithNull(): void
    {
        $this->assertTrue(SaFoxUtil::isEmpty(null));
    }

    public function testIsEmptyWithEmptyString(): void
    {
        $this->assertTrue(SaFoxUtil::isEmpty(''));
    }

    public function testIsEmptyWithNonEmptyString(): void
    {
        $this->assertFalse(SaFoxUtil::isEmpty('hello'));
    }

    public function testIsNotEmptyWithNonEmptyString(): void
    {
        $this->assertTrue(SaFoxUtil::isNotEmpty('hello'));
    }

    public function testIsNotEmptyWithNull(): void
    {
        $this->assertFalse(SaFoxUtil::isNotEmpty(null));
    }

    public function testIsNotEmptyWithEmptyString(): void
    {
        $this->assertFalse(SaFoxUtil::isNotEmpty(''));
    }

    // ---- inArray ----

    public function testInArrayFound(): void
    {
        $this->assertTrue(SaFoxUtil::inArray(['a', 'b', 'c'], 'b'));
    }

    public function testInArrayNotFound(): void
    {
        $this->assertFalse(SaFoxUtil::inArray(['a', 'b', 'c'], 'd'));
    }

    public function testInArrayStrictTypeCheck(): void
    {
        $this->assertFalse(SaFoxUtil::inArray(['1', '2', '3'], 1));
        $this->assertTrue(SaFoxUtil::inArray(['1', '2', '3'], '1'));
    }

    public function testInArrayEmptyArray(): void
    {
        $this->assertFalse(SaFoxUtil::inArray([], 'a'));
    }

    // ---- toString ----

    public function testToStringWithString(): void
    {
        $this->assertEquals('hello', SaFoxUtil::toString('hello'));
    }

    public function testToStringWithInt(): void
    {
        $this->assertEquals('123', SaFoxUtil::toString(123));
    }

    public function testToStringWithFloat(): void
    {
        $this->assertEquals('1.5', SaFoxUtil::toString(1.5));
    }

    public function testToStringWithBool(): void
    {
        $this->assertEquals('true', SaFoxUtil::toString(true));
        $this->assertEquals('false', SaFoxUtil::toString(false));
    }

    public function testToStringWithNull(): void
    {
        $this->assertEquals('', SaFoxUtil::toString(null));
    }

    public function testToStringWithArray(): void
    {
        $result = SaFoxUtil::toString(['a' => 1]);
        $this->assertJson($result);
        $this->assertEquals('{"a":1}', $result);
    }

    // ---- toJson / fromJson ----

    public function testToJson(): void
    {
        $json = SaFoxUtil::toJson(['name' => '张三', 'age' => 25]);
        $this->assertJson($json);
        $this->assertStringContainsString('张三', $json);
    }

    public function testFromJson(): void
    {
        $data = SaFoxUtil::fromJson('{"name":"张三","age":25}');
        $this->assertIsArray($data);
        $this->assertEquals('张三', $data['name']);
        $this->assertEquals(25, $data['age']);
    }

    public function testFromJsonAsObject(): void
    {
        $data = SaFoxUtil::fromJson('{"key":"value"}', false);
        $this->assertIsObject($data);
        $this->assertEquals('value', $data->key);
    }

    public function testToJsonFromJsonRoundTrip(): void
    {
        $original = ['key' => 'value', 'number' => 42, 'nested' => ['a' => 1]];
        $json = SaFoxUtil::toJson($original);
        $decoded = SaFoxUtil::fromJson($json);
        $this->assertEquals($original, $decoded);
    }

    // ---- valueToString / valueToInt ----

    public function testValueToStringWithNull(): void
    {
        $this->assertNull(SaFoxUtil::valueToString(null));
    }

    public function testValueToStringWithValue(): void
    {
        $this->assertEquals('42', SaFoxUtil::valueToString(42));
    }

    public function testValueToIntWithNull(): void
    {
        $this->assertNull(SaFoxUtil::valueToInt(null));
    }

    public function testValueToIntWithValue(): void
    {
        $this->assertEquals(42, SaFoxUtil::valueToInt('42'));
    }

    public function testValueToIntWithNonNumeric(): void
    {
        $this->assertEquals(0, SaFoxUtil::valueToInt('abc'));
    }

    // ---- getTime / getMsTime ----

    public function testGetTime(): void
    {
        $time = SaFoxUtil::getTime();
        $this->assertEqualsWithDelta(time(), $time, 1);
    }

    public function testGetMsTime(): void
    {
        $msTime = SaFoxUtil::getMsTime();
        $this->assertGreaterThan(0, $msTime);
        $this->assertGreaterThan(SaFoxUtil::getTime() * 1000 - 2000, $msTime);
    }
}
