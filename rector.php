<?php

declare(strict_types=1);

use Rector\Carbon\Rector\FuncCall\DateFuncCallToCarbonRector;
use Rector\Carbon\Rector\FuncCall\TimeFuncCallToCarbonRector;
use Rector\Carbon\Rector\MethodCall\DateTimeMethodCallToCarbonRector;
use Rector\Carbon\Rector\New_\DateTimeInstanceToCarbonRector;
use Rector\Config\RectorConfig;
use Rector\Exception\Configuration\InvalidConfigurationException;
use Rector\PHPUnit\PHPUnit110\Rector\Class_\NamedArgumentForDataProviderRector;
use Rector\Set\ValueObject\SetList;
use Rector\TypeDeclaration\Rector\ClassMethod\AddParamTypeDeclarationRector;

try {
    return RectorConfig::configure()
        ->withPaths([
            __DIR__ . '/src',
            __DIR__ . '/tests',
        ])
        ->withRules([
            NamedArgumentForDataProviderRector::class,
            AddParamTypeDeclarationRector::class,
            // DateTime to Carbon
            DateTimeMethodCallToCarbonRector::class,
            DateFuncCallToCarbonRector::class,
            TimeFuncCallToCarbonRector::class,
            DateTimeInstanceToCarbonRector::class,
            // NamedOptionalParametersRector::class
        ])
        // uncomment to reach your current PHP version
        ->withPhpSets(
            php82: true,
        )
        ->withTypeCoverageLevel(10)
        ->withCodingStyleLevel(10)
        ->withDeadCodeLevel(10)
        ->withCodeQualityLevel(10)
        ->withFluentCallNewLine()
        ->withImportNames()
        ->withSets([
            SetList::PHP_85,
            SetList::EARLY_RETURN,
            SetList::BEHAT_ANNOTATIONS_TO_ATTRIBUTES,
            SetList::GMAGICK_TO_IMAGICK,
            SetList::INSTANCEOF,
            // SetList::NAMING,
            // SetList::PRIVATIZATION,
            SetList::TYPE_DECLARATION_DOCBLOCKS,
        ]);
} catch (InvalidConfigurationException) {

}
