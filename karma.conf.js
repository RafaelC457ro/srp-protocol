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
        browsers: ['FirefoxHeadless', 'ChromeHeadless'],
        coverageReporter: {
            reporters: [{type: 'text-summary'}, {type: 'lcovonly'}]
        }
    });
};
