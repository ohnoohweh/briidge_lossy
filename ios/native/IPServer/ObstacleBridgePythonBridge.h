#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ObstacleBridgePythonBridge : NSObject

+ (instancetype)sharedBridge;
- (nullable NSDictionary *)sendMessage:(NSDictionary *)message error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
