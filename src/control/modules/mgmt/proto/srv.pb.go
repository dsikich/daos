// Code generated by protoc-gen-go. DO NOT EDIT.
// source: srv.proto

package proto

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type ListFeaturesParams struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ListFeaturesParams) Reset()         { *m = ListFeaturesParams{} }
func (m *ListFeaturesParams) String() string { return proto.CompactTextString(m) }
func (*ListFeaturesParams) ProtoMessage()    {}
func (*ListFeaturesParams) Descriptor() ([]byte, []int) {
	return fileDescriptor_srv_9df31151079c3eb2, []int{0}
}
func (m *ListFeaturesParams) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ListFeaturesParams.Unmarshal(m, b)
}
func (m *ListFeaturesParams) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ListFeaturesParams.Marshal(b, m, deterministic)
}
func (dst *ListFeaturesParams) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ListFeaturesParams.Merge(dst, src)
}
func (m *ListFeaturesParams) XXX_Size() int {
	return xxx_messageInfo_ListFeaturesParams.Size(m)
}
func (m *ListFeaturesParams) XXX_DiscardUnknown() {
	xxx_messageInfo_ListFeaturesParams.DiscardUnknown(m)
}

var xxx_messageInfo_ListFeaturesParams proto.InternalMessageInfo

type FeatureName struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *FeatureName) Reset()         { *m = FeatureName{} }
func (m *FeatureName) String() string { return proto.CompactTextString(m) }
func (*FeatureName) ProtoMessage()    {}
func (*FeatureName) Descriptor() ([]byte, []int) {
	return fileDescriptor_srv_9df31151079c3eb2, []int{1}
}
func (m *FeatureName) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FeatureName.Unmarshal(m, b)
}
func (m *FeatureName) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FeatureName.Marshal(b, m, deterministic)
}
func (dst *FeatureName) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FeatureName.Merge(dst, src)
}
func (m *FeatureName) XXX_Size() int {
	return xxx_messageInfo_FeatureName.Size(m)
}
func (m *FeatureName) XXX_DiscardUnknown() {
	xxx_messageInfo_FeatureName.DiscardUnknown(m)
}

var xxx_messageInfo_FeatureName proto.InternalMessageInfo

func (m *FeatureName) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type Feature struct {
	// The name of the feature.
	Fname *FeatureName `protobuf:"bytes,1,opt,name=fname,proto3" json:"fname,omitempty"`
	// The description of the feature.
	Description          string   `protobuf:"bytes,2,opt,name=description,proto3" json:"description,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Feature) Reset()         { *m = Feature{} }
func (m *Feature) String() string { return proto.CompactTextString(m) }
func (*Feature) ProtoMessage()    {}
func (*Feature) Descriptor() ([]byte, []int) {
	return fileDescriptor_srv_9df31151079c3eb2, []int{2}
}
func (m *Feature) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Feature.Unmarshal(m, b)
}
func (m *Feature) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Feature.Marshal(b, m, deterministic)
}
func (dst *Feature) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Feature.Merge(dst, src)
}
func (m *Feature) XXX_Size() int {
	return xxx_messageInfo_Feature.Size(m)
}
func (m *Feature) XXX_DiscardUnknown() {
	xxx_messageInfo_Feature.DiscardUnknown(m)
}

var xxx_messageInfo_Feature proto.InternalMessageInfo

func (m *Feature) GetFname() *FeatureName {
	if m != nil {
		return m.Fname
	}
	return nil
}

func (m *Feature) GetDescription() string {
	if m != nil {
		return m.Description
	}
	return ""
}

func init() {
	proto.RegisterType((*ListFeaturesParams)(nil), "proto.ListFeaturesParams")
	proto.RegisterType((*FeatureName)(nil), "proto.FeatureName")
	proto.RegisterType((*Feature)(nil), "proto.Feature")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// MgmtControlClient is the client API for MgmtControl service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type MgmtControlClient interface {
	GetFeature(ctx context.Context, in *FeatureName, opts ...grpc.CallOption) (*Feature, error)
	ListFeatures(ctx context.Context, in *ListFeaturesParams, opts ...grpc.CallOption) (MgmtControl_ListFeaturesClient, error)
}

type mgmtControlClient struct {
	cc *grpc.ClientConn
}

func NewMgmtControlClient(cc *grpc.ClientConn) MgmtControlClient {
	return &mgmtControlClient{cc}
}

func (c *mgmtControlClient) GetFeature(ctx context.Context, in *FeatureName, opts ...grpc.CallOption) (*Feature, error) {
	out := new(Feature)
	err := c.cc.Invoke(ctx, "/proto.MgmtControl/GetFeature", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mgmtControlClient) ListFeatures(ctx context.Context, in *ListFeaturesParams, opts ...grpc.CallOption) (MgmtControl_ListFeaturesClient, error) {
	stream, err := c.cc.NewStream(ctx, &_MgmtControl_serviceDesc.Streams[0], "/proto.MgmtControl/ListFeatures", opts...)
	if err != nil {
		return nil, err
	}
	x := &mgmtControlListFeaturesClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type MgmtControl_ListFeaturesClient interface {
	Recv() (*Feature, error)
	grpc.ClientStream
}

type mgmtControlListFeaturesClient struct {
	grpc.ClientStream
}

func (x *mgmtControlListFeaturesClient) Recv() (*Feature, error) {
	m := new(Feature)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// MgmtControlServer is the server API for MgmtControl service.
type MgmtControlServer interface {
	GetFeature(context.Context, *FeatureName) (*Feature, error)
	ListFeatures(*ListFeaturesParams, MgmtControl_ListFeaturesServer) error
}

func RegisterMgmtControlServer(s *grpc.Server, srv MgmtControlServer) {
	s.RegisterService(&_MgmtControl_serviceDesc, srv)
}

func _MgmtControl_GetFeature_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FeatureName)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MgmtControlServer).GetFeature(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.MgmtControl/GetFeature",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MgmtControlServer).GetFeature(ctx, req.(*FeatureName))
	}
	return interceptor(ctx, in, info, handler)
}

func _MgmtControl_ListFeatures_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(ListFeaturesParams)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(MgmtControlServer).ListFeatures(m, &mgmtControlListFeaturesServer{stream})
}

type MgmtControl_ListFeaturesServer interface {
	Send(*Feature) error
	grpc.ServerStream
}

type mgmtControlListFeaturesServer struct {
	grpc.ServerStream
}

func (x *mgmtControlListFeaturesServer) Send(m *Feature) error {
	return x.ServerStream.SendMsg(m)
}

var _MgmtControl_serviceDesc = grpc.ServiceDesc{
	ServiceName: "proto.MgmtControl",
	HandlerType: (*MgmtControlServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetFeature",
			Handler:    _MgmtControl_GetFeature_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ListFeatures",
			Handler:       _MgmtControl_ListFeatures_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "srv.proto",
}

func init() { proto.RegisterFile("srv.proto", fileDescriptor_srv_9df31151079c3eb2) }

var fileDescriptor_srv_9df31151079c3eb2 = []byte{
	// 188 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x2c, 0x2e, 0x2a, 0xd3,
	0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0x05, 0x53, 0x4a, 0x22, 0x5c, 0x42, 0x3e, 0x99, 0xc5,
	0x25, 0x6e, 0xa9, 0x89, 0x25, 0xa5, 0x45, 0xa9, 0xc5, 0x01, 0x89, 0x45, 0x89, 0xb9, 0xc5, 0x4a,
	0x8a, 0x5c, 0xdc, 0x50, 0x11, 0xbf, 0xc4, 0xdc, 0x54, 0x21, 0x21, 0x2e, 0x96, 0xbc, 0xc4, 0xdc,
	0x54, 0x09, 0x46, 0x05, 0x46, 0x0d, 0xce, 0x20, 0x30, 0x5b, 0x29, 0x94, 0x8b, 0x1d, 0xaa, 0x44,
	0x48, 0x83, 0x8b, 0x35, 0x0d, 0x2e, 0xcf, 0x6d, 0x24, 0x04, 0xb1, 0x41, 0x0f, 0xc9, 0x84, 0x20,
	0x88, 0x02, 0x21, 0x05, 0x2e, 0xee, 0x94, 0xd4, 0xe2, 0xe4, 0xa2, 0xcc, 0x82, 0x92, 0xcc, 0xfc,
	0x3c, 0x09, 0x26, 0xb0, 0x79, 0xc8, 0x42, 0x46, 0x0d, 0x8c, 0x5c, 0xdc, 0xbe, 0xe9, 0xb9, 0x25,
	0xce, 0xf9, 0x79, 0x25, 0x45, 0xf9, 0x39, 0x42, 0x46, 0x5c, 0x5c, 0xee, 0xa9, 0x30, 0xe7, 0x09,
	0x61, 0x31, 0x5a, 0x8a, 0x0f, 0x55, 0x4c, 0x89, 0x41, 0xc8, 0x96, 0x8b, 0x07, 0xd9, 0x4f, 0x42,
	0x92, 0x50, 0x15, 0x98, 0x1e, 0xc5, 0xd4, 0x6c, 0xc0, 0x98, 0xc4, 0x06, 0x16, 0x32, 0x06, 0x04,
	0x00, 0x00, 0xff, 0xff, 0x9e, 0x42, 0xb8, 0xe2, 0x2d, 0x01, 0x00, 0x00,
}
