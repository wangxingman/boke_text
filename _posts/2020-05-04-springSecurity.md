# springSecurity

## 1、介绍

- 认证 （你是谁）

- 授权 （你能干什么）

- 攻击防护 （防止伪造身份）

  

  其核心就是一组过滤器链，项目启动后将会自动配置。最核心的就是 Basic Authentication Filter 用来认证用户的身份，一个在spring security中一种过滤器处理一种认证方式。 

 ![img](https://img-blog.csdnimg.cn/20190116102342618.jpg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzIyMTcyMTMz,size_16,color_FFFFFF,t_70) 



## 2、源码解析

### 1、登录原理

https://www.jianshu.com/p/a65f883de0c1

#### 1、UsernamePasswordAuthenticationFilter



##### 1、父类

1、**执行父类的过滤器**

 `AbstractAuthenticationProcessingFilter.doFilter()` 

 此方法首先判断当前的filter是否可以处理当前请求，不可以的话则交给下一个filter处理。 

2、 **调用此抽象类的子类** 

 `UsernamePasswordAuthenticationFilter.attemptAuthentication(request, response)` 

**3、认证成功后做一些成功后的`session`操作**

```java
sessionStrategy.onAuthentication(authResult, request, response);
```

 **4、最终认证成功后的相关回调方法，主要将当前的认证信息放到`SecurityContextHolder`中并调用成功处理器做相应的操作。** 

```java
successfulAuthentication(request, response, chain, authResult);
```

##### 2、子类

 **1、父类的`authResult = attemptAuthentication(request, response);`触发了自类的方法。** 

 **2、此方法首先判断请求方式是不是POST提交，必须是POST** 

 **3、从请求中获取`username`和`password`，并做一些处理** 

 **4、封装`Authenticaiton`类的实现类`UsernamePasswordAuthenticationToken`** 

 **5、调用`AuthenticationManager`的`authenticate`方法进行验证** 

```java
return this.getAuthenticationManager().authenticate(authRequest);
```

##### 3、AuthenticationManager

###### 1、触发

**return this.getAuthenticationManager().authenticate(authRequest);**

######  2、此方法遍历所有的Providers，然后依次执行验证方法看是否支持 

```
// 拿到全部的provider
Iterator e = this.getProviders().iterator();
// 遍历provider
while(e.hasNext()) {
    AuthenticationProvider provider = (AuthenticationProvider)e.next();
    // 挨着个的校验是否支持当前token
    if(provider.supports(toTest)) {
        if(debug) {
            logger.debug("Authentication attempt using " + provider.getClass().getName());
        }
    }
}
```



###### 4、**若没一个`provider`验证成功，则交由父类来尝试处理**

```java
// 若没有一个支持，则尝试交给父类来执行
if(result == null && this.parent != null) {
    try {
        result = this.parent.authenticate(authentication);
    } catch (ProviderNotFoundException var9) {
        ;
    } catch (AuthenticationException var10) {
        lastException = var10;
    }
}
```

##### 4、AuthenticationProvider处理流程

##### 1、触发 

```java
result = provider.authenticate(authentication);
```

#####  **2、`DaoAuthenticationProvider`** 

#####  **3、继承了`AbstractUserDetailsAuthenticationProvider`** 

##### **4、`AbstractUserDetailsAuthenticationProvider.authenticate()`首先调用了`user = this.retrieveUser(username, (UsernamePasswordAuthenticationToken)authentication);`**

> PS：调用的是`DaoAuthenticationProvider.retrieveUser()`

##### **5、调用我们自己的业务处理类**

```java
loadedUser = this.getUserDetailsService().loadUserByUsername(username);
```

##### 6、 **调用完`retrieveUser`方法继续回到抽象类的`authenticate`方法** 

#####  **7、首先做一些检查** 

```java
/*
* 前检查由DefaultPreAuthenticationChecks类实现（主要判断当前用户是否锁定，过期，冻结
* User接口）
*/
this.preAuthenticationChecks.check(user);
// 检测用户密码是否过期
this.postAuthenticationChecks.check(user);
```



##### 8、 **调用`createSuccessAuthentication`方法进行授权成功** 



##### 9、回到起点

 AbstractAuthenticationProcessingFilter.doFilter()

### 2、记住我原理

 https://blog.csdn.net/qq_36144258/article/details/79395013 

#### 1、介绍

1、登录成功会去数据库保存token

2、客户端请求会经过 **RemberMeAuenticationFilter** ， 读取给RemberMeService ，数据库去查

3、 就会把Username用户名取出来，取出来之后会调用UserDetailsService，获取用户信息，然后把用户信息放入到SecurityContext里面。 



#### 2、源码解析

1、 登陆成功后的一个认证处理，在AbstracAuthenticationProcessingFilter 

 ![这里写图片描述](https://img-blog.csdn.net/20180228074452136?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvcXFfMzYxNDQyNTg=/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70) 



2、 PersistentTokenBasedRememberMeservices 

 ![这里写图片描述](https://img-blog.csdn.net/20180228074609381?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvcXFfMzYxNDQyNTg=/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70) 



3、 RemembermeAuthenticationFilter 

 ![这里写图片描述](https://img-blog.csdn.net/20180228074637320?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvcXFfMzYxNDQyNTg=/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70) 



### 3、退出原理

 https://blog.csdn.net/dandandeshangni/article/details/79098629 

#### 1、介绍

1. 清除`Cookie`
2. 清除当前用户的`remember-me`记录
3. 使当前`session`失效
4. 清空当前的`SecurityContext`
5. 重定向到登录界面



#### 2、源码解析

<!-- LogoutFilter-->

```java
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        //#1.匹配到/logout请求
        if (requiresLogout(request, response)) {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();

            if (logger.isDebugEnabled()) {
                logger.debug("Logging out user '" + auth
                        + "' and transferring to logout destination");
            }
            //#2.处理1-4步
            this.handler.logout(request, response, auth);
            //#3.重定向到注册界面
            logoutSuccessHandler.onLogoutSuccess(request, response, auth);
    
            return;
        }
    
        chain.doFilter(request, response);
    }



```

##### 1、匹配当前拦截的请求

##### 2、处理 清空Cookie、remember-me、session和SecurityContext

1、CookieClearingLogoutHandler清空Cookie
2、PersistentTokenBasedRememberMeServices清空remember-me
3、SecurityContextLogoutHandler 使当前session无效,清空当前的SecurityContext

##### 3、重定向到登录界面

1、匹配当前拦截的请求
2、处理 清空Cookie、remember-me、session和SecurityContext
3、重定向到登录界面



## 3、配合jwt使用 

 https://www.jianshu.com/p/5b9f1f4de88d 


