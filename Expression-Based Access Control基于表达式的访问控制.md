# 基于表达式的访问控制(Expression-Based Access Control)


### Common Built-In Expressions 通用的内建表达式

|表达式|示例|
|---|---|
|hasRole(String role)|hasRole('admin')|
|hasAnyRole(String…​ roles)|hasAnyRole('admin', 'user')|
|hasAuthority(String authority)|hasAuthority('read')|
|hasAnyAuthority(String…​ authorities)|hasAnyAuthority('read', 'write')|
|principal||
|authentication||
|permitAll||
|denyAll||
|isAnonymous()||
|isRememberMe()||
|isAuthenticated()||
|isFullyAuthenticated()||
|hasPermission(Object target, Object permission)|hasPermission(domainObject, 'read')|
|hasPermission(Object targetId, String targetType, Object permission)|hasPermission(1, 'com.example.domain.Message', 'read')|
|hasIpAddress(String ipAddressExpression)|hasIpAddress('192.168.1.0/24')|
|||
|||
|||
|||


### Referring to Beans in Web Security Expressions 引用bean的表达式

```
public class WebSecurity {
        public boolean check(Authentication authentication, HttpServletRequest request) {
                ...
        }
}

http
    .authorizeRequests(authorize -> authorize
        .antMatchers("/user/**").access("@webSecurity.check(authentication,request)")
        ...
    )
    
```


### Path Variables in Web Security Expressions

```
public class WebSecurity {
        public boolean checkUserId(Authentication authentication, int id) {
                ...
        }
}

http
    .authorizeRequests(authorize -> authorize
        .antMatchers("/user/{userId}/**").access("@webSecurity.checkUserId(authentication,#userId)")
        ...
    );
```

### Method Security Expressions

```
@PreAuthorize("hasRole('USER')")
public void create(Contact contact);


@PreAuthorize("hasPermission(#contact, 'admin')")
public void deletePermission(Contact contact, Sid recipient, Permission permission);


@PreAuthorize("#c.name == authentication.name")
public void doSomething(@P("c") Contact contact);

@PreAuthorize("#n == authentication.name")
Contact findContactByName(@Param("n") String name);

@PreAuthorize("#contact.name == authentication.name")
public void doSomething(Contact contact);

@PreAuthorize("hasRole('USER')")
@PostFilter("hasPermission(filterObject, 'read') or hasPermission(filterObject, 'admin')")
public List<Contact> getAll();




```










