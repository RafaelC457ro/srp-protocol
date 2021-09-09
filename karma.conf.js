const process = require('process');
process.env.CHROME_BIN = require('puppeteer').executablePath();

module.exports = function(config) {
    config.set({
        frameworks: ['jasmine', 'karma-typescript'],
        files: [
            {
                pattern: 'src/**/*.ts'
            },
            {
                pattern: 'test/**/*.ts'
            }
        ],
        karmaTypescriptConfig: {
            tsconfig: './tsconfig.json',
            compilerOptions: {
                sourceMap: true,
                module: 'commonjs' // overrides tsconfig
            }
        },
        preprocessors: {
            'src/**/*.ts': ['karma-typescript', 'coverage'],
            'test/**/*.ts': ['karma-typescript']
        },
        reporters: ['progress', 'karma-typescript', 'coverage'],
        browsers: ['FirefoxHeadless', 'ChromeHeadlessNoSandbox'],
        customLaunchers: {
            ChromeHeadlessNoSandbox: {
                base: 'ChromeHeadless',
                flags: [
                    '--no-sandbox',
                    '--headless',
                    '--disable-gpu',
                    '--disable-translate',
                    '--disable-extensions'
                ]
            }
        },
        coverageReporter: {
            reporters: [{type: 'text-summary'}, {type: 'lcovonly'}]
        }
    });
};
