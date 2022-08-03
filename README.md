# shucang


### 安装

```shell
go get github.com/vtoday/shucang
```

### 客户端初始化

```go
    import (
        "github.com/vtoday/shucang"
    )

    privateKey := "MIIEvAIBADANBgkq......jkl9aD/5k8I/Hag=="
    publicKey := "MIIBIjANBgkq......IDAQAB"

    opens := []shucang.OptionFunc{}
    client, err := shucang.New("1001", privateKey, publicKey, false, opens...)
    if err != nil {
        return
    }
```

### 调用`转入(寄售)藏品`接口

```go
    import (
        "github.com/vtoday/shucang"
    )

    param := shucang.CollectionExchangeParam{}
    param.CollectionHash = "0xbb9d8e0ae3e56b095f429027b87ed3ed446e769e1ea0eb6a2dfdb98dd1dce5b6"
    param.OwnerWalletAddress = "ccccccccccccccccccccccccccccc"
    param.UserId = "567"

    fmt.Println(client.Exchange(param))
```

### 提供`查询用户信息`接口

```go
    import (
        "github.com/vtoday/shucang"
    )

    req *http.Request := ... //TODO 获取请求request
    request, err := shucang.ParseRequest(req)
    if err != nil {
        return
    }

    //校验请求
    if ok, e := client.VerifyRequestSign(request); !ok {
        return
    }

    //解密请求data
    data, e := client.DecryptRequestData(request)

    var param shucang.CollectionExchangeParam
    if err := json.Unmarshal([]byte(data), &param); err != nil {
        return
    }
```