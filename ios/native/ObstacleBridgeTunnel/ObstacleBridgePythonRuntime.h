#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ObstacleBridgePythonRuntime : NSObject

- (BOOL)startWithProviderConfigurationJSON:(NSString *)providerConfigurationJSON
                          parentBundlePath:(NSString *)parentBundlePath
                                     error:(NSError **)error;
- (void)stop;
- (NSString *)statusJSON;

@end

NS_ASSUME_NONNULL_END
