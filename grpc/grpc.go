package grpc

import (
	"context"

	"google.golang.org/grpc"
)

/*
从stream.proto 生成 stream.pb.go 和 stream_grpc.pb.go:

protoc --go_out=. --go_opt=paths=source_relative \
    --go-grpc_out=. --go-grpc_opt=paths=source_relative \
    stream.proto

stream.pb.go 可以无视, 是数据编码; 主要观察 stream_grpc.pb.go

这里参考v2ray/xray, 它们的 Tun的意思应该是 network tunnel, 没啥的.
GunService 看不懂,可能是瞎编的; 或者可能是 "gprc tunnel"的简写吧。但是就算简写也要是 gTun。毕竟gun谐音不好。

不过查看一下v2ray的合并grpc功能的pr，
https://github.com/v2fly/v2ray-core/pull/757

似乎是来自 Qv2ray/gun 这个库；总之也一样，那么那个库的起名还是很怪。

但是因为我们使用自定义ServiceName的方法，所以似乎 GunService的名字无所谓，可以随便改

我直接把 GunService名称改成了 “Stream”，不影响的。反正我们自定义内部真实名称.

实测名称是不影响的， 一样兼容xray/v2ray的 grpc。因为 我们自定义实际的 ServiceDesc
*/

// ServerDesc_withName 用于生成指定ServiceName名称 的 grpc.ServiceDesc.
// 默认proto生成的 Stream_ServiceDesc 变量 的名称是固定的, 见 stream_grpc.pb.go 的最下方.
func ServerDesc_withName(name string) grpc.ServiceDesc {
	return grpc.ServiceDesc{
		ServiceName: name,
		HandlerType: (*StreamServer)(nil),
		Methods:     []grpc.MethodDesc{},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    "Tun",
				Handler:       _Stream_Tun_Handler,
				ServerStreams: true,
				ClientStreams: true,
			},
		},
		Metadata: "gun.proto",
	}
}

func registerStreamServer_withName(s *grpc.Server, srv StreamServer, name string) {
	desc := ServerDesc_withName(name)
	s.RegisterService(&desc, srv)
}

// 即 可自定义服务名的 StreamClient
type streamClient_withName interface {
	StreamClient

	tun_withName(ctx context.Context, name string, opts ...grpc.CallOption) (Stream_TunClient, error)
}

//比照 protoc生成的 stream_grpc.pb.go 中的 Tun方法
// 我们加一个 tun_withName 方法, 可以自定义服务名称, 该方法让 streamClient实现 streamClient_withName 接口
func (c *streamClient) tun_withName(ctx context.Context, name string, opts ...grpc.CallOption) (Stream_TunClient, error) {
	//这里ctx不能为nil，否则会报错
	if ctx == nil {
		ctx = context.Background()
	}
	stream, err := c.cc.NewStream(ctx, &ServerDesc_withName(name).Streams[0], "/"+name+"/Tun", opts...)
	if err != nil {
		return nil, err
	}
	x := &streamTunClient{stream}
	return x, nil
}
