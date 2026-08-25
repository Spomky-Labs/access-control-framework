<?php

declare(strict_types=1);

namespace AccessControl\Tests\Bundle\Resources;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use function dirname;
use function sprintf;

/**
 * The toolbar icon travelled here with the panel, and so did the check WebProfilerBundle runs on
 * its own: without the three attributes below the toolbar lays out wrong.
 */
final class IconTest extends TestCase
{
    #[DataProvider('provideIconFilePaths')]
    public function testIconFileContents($iconFilePath)
    {
        $iconFilePath = realpath($iconFilePath);
        $svgFileContents = file_get_contents($iconFilePath);

        static::assertStringContainsString('xmlns="http://www.w3.org/2000/svg"', (string) $svgFileContents, sprintf('The SVG metadata of the "%s" icon must use "http://www.w3.org/2000/svg" as its "xmlns" value.', $iconFilePath));

        static::assertMatchesRegularExpression('~<svg .* width="\d+".+>.*</svg>~s', $svgFileContents, sprintf('The SVG file of the "%s" icon must include a "width" attribute.', $iconFilePath));

        static::assertMatchesRegularExpression('~<svg .* height="\d+".+>.*</svg>~s', $svgFileContents, sprintf('The SVG file of the "%s" icon must include a "height" attribute.', $iconFilePath));

        static::assertMatchesRegularExpression('~<svg .* viewBox="0 0 \d+ \d+".+>.*</svg>~s', $svgFileContents, sprintf('The SVG file of the "%s" icon must include a "viewBox" attribute.', $iconFilePath));
    }

    public static function provideIconFilePaths(): array
    {
        return array_map(static fn ($filePath) => (array) $filePath, glob(dirname(__DIR__, 3) . '/src/symfony/src/Resources/views/Icon/*.svg'));
    }
}
