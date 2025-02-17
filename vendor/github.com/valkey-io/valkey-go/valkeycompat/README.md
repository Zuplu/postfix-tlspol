## Go-redis like API Adapter

Though it is easier to know what command will be sent to valkey at first glance if the command is constructed by the command builder,
users may sometimes feel it too verbose to write.

For users who don't like the command builder, `valkeycompat.Adapter`, contributed mainly by [@418Coffee](https://github.com/418Coffee), is an alternative.
It is a high level API which is close to go-redis's `Cmdable` interface.

### Migrating from go-redis

You can also try adapting `valkey` with existing go-redis code by replacing go-redis's `UniversalClient` with `valkeycompat.Adapter`.

### Client side caching example

To use client side caching with `valkeycompat.Adapter`, chain `Cache(ttl)` call in front of supported command.

```golang
package main

import (
	"context"
	"time"
	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeycompat"
)

func main() {
	ctx := context.Background()
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{"127.0.0.1:6379"}})
	if err != nil {
		panic(err)
	}
	defer client.Close()

	compat := valkeycompat.NewAdapter(client)
	ok, _ := compat.SetNX(ctx, "key", "val", time.Second).Result()

	// with client side caching
	res, _ := compat.Cache(time.Second).Get(ctx, "key").Result()
}
```

### Pipeline example

```golang
package main

import (
	"context"
	"fmt"
	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeycompat"
)

func main() {
	ctx := context.Background()
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{"127.0.0.1:6379"}})
	if err != nil {
		panic(err)
	}
	defer client.Close()

	rdb := valkeycompat.NewAdapter(client)
	cmds, err := rdb.Pipelined(ctx, func(pipe valkeycompat.Pipeliner) error {
		for i := 0; i < 100; i++ {
			pipe.Set(ctx, fmt.Sprintf("key%d", i), i, 0)
			pipe.Get(ctx, fmt.Sprintf("key%d", i))
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
	for _, cmd := range cmds {
		fmt.Println(cmd.(*valkeycompat.StringCmd).Val())
	}
}
```

### Transaction example

```golang
package main

import (
	"context"
	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeycompat"
)

func main() {
	ctx := context.Background()
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{"127.0.0.1:6379"}})
	if err != nil {
		panic(err)
	}
	defer client.Close()

	key := "my_counter"
	rdb := valkeycompat.NewAdapter(client)
	txf := func(tx valkeycompat.Tx) error {
		n, err := tx.Get(ctx, key).Int()
		if err != nil && err != valkeycompat.Nil {
			return err
		}
		// Operation is commited only if the watched keys remain unchanged.
		_, err = tx.TxPipelined(ctx, func(pipe valkeycompat.Pipeliner) error {
			pipe.Set(ctx, key, n+1, 0)
			return nil
		})
		return err
	}
	for {
		err := rdb.Watch(ctx, txf, key)
		if err == nil {
			break
		} else if err == valkeycompat.TxFailedErr {
			// Optimistic lock lost. Retry if the key has been changed.
			continue
		}
		panic(err)
	}
}
```


### PubSub example

```golang
package main

import (
	"context"
	"fmt"
	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeycompat"
	"strconv"
)

func main() {
	ctx := context.Background()
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{"127.0.0.1:6379"}})
	if err != nil {
		panic(err)
	}
	defer client.Close()

	rdb := valkeycompat.NewAdapter(client)
	pubsub := rdb.Subscribe(ctx, "mychannel1")
	defer pubsub.Close()

	go func() {
		for i := 0; ; i++ {
			if err := rdb.Publish(ctx, "mychannel1", strconv.Itoa(i)).Err(); err != nil {
				panic(err)
			}
		}
	}()
	for {
		msg, err := pubsub.ReceiveMessage(ctx)
		if err != nil {
			panic(err)
		}
		fmt.Println(msg.Channel, msg.Payload)
	}
}
```

### Lua script example

```golang
package main

import (
	"context"
	"fmt"
	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/valkeycompat"
)

var incrBy = valkeycompat.NewScript(`
local key = KEYS[1]
local change = ARGV[1]
local value = redis.call("GET", key)
if not value then
  value = 0
end
value = value + change
redis.call("SET", key, value)
return value
`)

func main() {
	ctx := context.Background()
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{"127.0.0.1:6379"}})
	if err != nil {
		panic(err)
	}
	defer client.Close()

	rdb := valkeycompat.NewAdapter(client)
	keys := []string{"my_counter"}
	values := []interface{}{+1}
	fmt.Println(incrBy.Run(ctx, rdb, keys, values...).Int())
}
```

### Methods not yet implemented in the adapter

* `HExpire`, `HPExpire`, `HTTL`, and `HPTTL` related methods.
* `FTSearch`, `FTAggregate`, `FTCreate`, and `FTDropIndex` related methods.

For more details, please refer to those `TODO` marks in the [./adapter.go](./adapter.go)
