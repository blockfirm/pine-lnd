// Code generated by protoc-gen-go. DO NOT EDIT.
// source: pine.proto

package pine

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type SignMessageRequest struct {
	// Message to sign.
	Message []byte `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
	// Public key of the private key to sign with (65 bytes uncompressed).
	PublicKey            []byte   `protobuf:"bytes,2,opt,name=publicKey,proto3" json:"publicKey,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SignMessageRequest) Reset()         { *m = SignMessageRequest{} }
func (m *SignMessageRequest) String() string { return proto.CompactTextString(m) }
func (*SignMessageRequest) ProtoMessage()    {}
func (*SignMessageRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_2d4b5db5d7eac1f0, []int{0}
}

func (m *SignMessageRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignMessageRequest.Unmarshal(m, b)
}
func (m *SignMessageRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignMessageRequest.Marshal(b, m, deterministic)
}
func (m *SignMessageRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignMessageRequest.Merge(m, src)
}
func (m *SignMessageRequest) XXX_Size() int {
	return xxx_messageInfo_SignMessageRequest.Size(m)
}
func (m *SignMessageRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_SignMessageRequest.DiscardUnknown(m)
}

var xxx_messageInfo_SignMessageRequest proto.InternalMessageInfo

func (m *SignMessageRequest) GetMessage() []byte {
	if m != nil {
		return m.Message
	}
	return nil
}

func (m *SignMessageRequest) GetPublicKey() []byte {
	if m != nil {
		return m.PublicKey
	}
	return nil
}

type SignMessageResponse struct {
	// Signature of the given message (DER-encoded).
	Signature            []byte   `protobuf:"bytes,1,opt,name=signature,proto3" json:"signature,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *SignMessageResponse) Reset()         { *m = SignMessageResponse{} }
func (m *SignMessageResponse) String() string { return proto.CompactTextString(m) }
func (*SignMessageResponse) ProtoMessage()    {}
func (*SignMessageResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_2d4b5db5d7eac1f0, []int{1}
}

func (m *SignMessageResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SignMessageResponse.Unmarshal(m, b)
}
func (m *SignMessageResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SignMessageResponse.Marshal(b, m, deterministic)
}
func (m *SignMessageResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SignMessageResponse.Merge(m, src)
}
func (m *SignMessageResponse) XXX_Size() int {
	return xxx_messageInfo_SignMessageResponse.Size(m)
}
func (m *SignMessageResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_SignMessageResponse.DiscardUnknown(m)
}

var xxx_messageInfo_SignMessageResponse proto.InternalMessageInfo

func (m *SignMessageResponse) GetSignature() []byte {
	if m != nil {
		return m.Signature
	}
	return nil
}

type ListUnspentWitnessRequest struct {
	MinConfirmations     int32    `protobuf:"varint,1,opt,name=minConfirmations,proto3" json:"minConfirmations,omitempty"`
	MaxConfirmations     int32    `protobuf:"varint,2,opt,name=maxConfirmations,proto3" json:"maxConfirmations,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ListUnspentWitnessRequest) Reset()         { *m = ListUnspentWitnessRequest{} }
func (m *ListUnspentWitnessRequest) String() string { return proto.CompactTextString(m) }
func (*ListUnspentWitnessRequest) ProtoMessage()    {}
func (*ListUnspentWitnessRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_2d4b5db5d7eac1f0, []int{2}
}

func (m *ListUnspentWitnessRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ListUnspentWitnessRequest.Unmarshal(m, b)
}
func (m *ListUnspentWitnessRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ListUnspentWitnessRequest.Marshal(b, m, deterministic)
}
func (m *ListUnspentWitnessRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ListUnspentWitnessRequest.Merge(m, src)
}
func (m *ListUnspentWitnessRequest) XXX_Size() int {
	return xxx_messageInfo_ListUnspentWitnessRequest.Size(m)
}
func (m *ListUnspentWitnessRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ListUnspentWitnessRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ListUnspentWitnessRequest proto.InternalMessageInfo

func (m *ListUnspentWitnessRequest) GetMinConfirmations() int32 {
	if m != nil {
		return m.MinConfirmations
	}
	return 0
}

func (m *ListUnspentWitnessRequest) GetMaxConfirmations() int32 {
	if m != nil {
		return m.MaxConfirmations
	}
	return 0
}

type ListUnspentWitnessResponse struct {
	Utxos                []*Utxo  `protobuf:"bytes,1,rep,name=utxos,proto3" json:"utxos,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ListUnspentWitnessResponse) Reset()         { *m = ListUnspentWitnessResponse{} }
func (m *ListUnspentWitnessResponse) String() string { return proto.CompactTextString(m) }
func (*ListUnspentWitnessResponse) ProtoMessage()    {}
func (*ListUnspentWitnessResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_2d4b5db5d7eac1f0, []int{3}
}

func (m *ListUnspentWitnessResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ListUnspentWitnessResponse.Unmarshal(m, b)
}
func (m *ListUnspentWitnessResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ListUnspentWitnessResponse.Marshal(b, m, deterministic)
}
func (m *ListUnspentWitnessResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ListUnspentWitnessResponse.Merge(m, src)
}
func (m *ListUnspentWitnessResponse) XXX_Size() int {
	return xxx_messageInfo_ListUnspentWitnessResponse.Size(m)
}
func (m *ListUnspentWitnessResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ListUnspentWitnessResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ListUnspentWitnessResponse proto.InternalMessageInfo

func (m *ListUnspentWitnessResponse) GetUtxos() []*Utxo {
	if m != nil {
		return m.Utxos
	}
	return nil
}

type Utxo struct {
	AddressType          uint32   `protobuf:"varint,1,opt,name=addressType,proto3" json:"addressType,omitempty"`
	Value                int64    `protobuf:"varint,2,opt,name=value,proto3" json:"value,omitempty"`
	Confirmations        int64    `protobuf:"varint,3,opt,name=confirmations,proto3" json:"confirmations,omitempty"`
	PkScript             []byte   `protobuf:"bytes,4,opt,name=pkScript,proto3" json:"pkScript,omitempty"`
	TransactionHash      []byte   `protobuf:"bytes,5,opt,name=transactionHash,proto3" json:"transactionHash,omitempty"`
	Vout                 uint32   `protobuf:"varint,6,opt,name=vout,proto3" json:"vout,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Utxo) Reset()         { *m = Utxo{} }
func (m *Utxo) String() string { return proto.CompactTextString(m) }
func (*Utxo) ProtoMessage()    {}
func (*Utxo) Descriptor() ([]byte, []int) {
	return fileDescriptor_2d4b5db5d7eac1f0, []int{4}
}

func (m *Utxo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Utxo.Unmarshal(m, b)
}
func (m *Utxo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Utxo.Marshal(b, m, deterministic)
}
func (m *Utxo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Utxo.Merge(m, src)
}
func (m *Utxo) XXX_Size() int {
	return xxx_messageInfo_Utxo.Size(m)
}
func (m *Utxo) XXX_DiscardUnknown() {
	xxx_messageInfo_Utxo.DiscardUnknown(m)
}

var xxx_messageInfo_Utxo proto.InternalMessageInfo

func (m *Utxo) GetAddressType() uint32 {
	if m != nil {
		return m.AddressType
	}
	return 0
}

func (m *Utxo) GetValue() int64 {
	if m != nil {
		return m.Value
	}
	return 0
}

func (m *Utxo) GetConfirmations() int64 {
	if m != nil {
		return m.Confirmations
	}
	return 0
}

func (m *Utxo) GetPkScript() []byte {
	if m != nil {
		return m.PkScript
	}
	return nil
}

func (m *Utxo) GetTransactionHash() []byte {
	if m != nil {
		return m.TransactionHash
	}
	return nil
}

func (m *Utxo) GetVout() uint32 {
	if m != nil {
		return m.Vout
	}
	return 0
}

type LockOutpointRequest struct {
	Hash                 []byte   `protobuf:"bytes,1,opt,name=hash,proto3" json:"hash,omitempty"`
	Index                uint32   `protobuf:"varint,2,opt,name=index,proto3" json:"index,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LockOutpointRequest) Reset()         { *m = LockOutpointRequest{} }
func (m *LockOutpointRequest) String() string { return proto.CompactTextString(m) }
func (*LockOutpointRequest) ProtoMessage()    {}
func (*LockOutpointRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_2d4b5db5d7eac1f0, []int{5}
}

func (m *LockOutpointRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LockOutpointRequest.Unmarshal(m, b)
}
func (m *LockOutpointRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LockOutpointRequest.Marshal(b, m, deterministic)
}
func (m *LockOutpointRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LockOutpointRequest.Merge(m, src)
}
func (m *LockOutpointRequest) XXX_Size() int {
	return xxx_messageInfo_LockOutpointRequest.Size(m)
}
func (m *LockOutpointRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_LockOutpointRequest.DiscardUnknown(m)
}

var xxx_messageInfo_LockOutpointRequest proto.InternalMessageInfo

func (m *LockOutpointRequest) GetHash() []byte {
	if m != nil {
		return m.Hash
	}
	return nil
}

func (m *LockOutpointRequest) GetIndex() uint32 {
	if m != nil {
		return m.Index
	}
	return 0
}

type LockOutpointResponse struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LockOutpointResponse) Reset()         { *m = LockOutpointResponse{} }
func (m *LockOutpointResponse) String() string { return proto.CompactTextString(m) }
func (*LockOutpointResponse) ProtoMessage()    {}
func (*LockOutpointResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_2d4b5db5d7eac1f0, []int{6}
}

func (m *LockOutpointResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_LockOutpointResponse.Unmarshal(m, b)
}
func (m *LockOutpointResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_LockOutpointResponse.Marshal(b, m, deterministic)
}
func (m *LockOutpointResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LockOutpointResponse.Merge(m, src)
}
func (m *LockOutpointResponse) XXX_Size() int {
	return xxx_messageInfo_LockOutpointResponse.Size(m)
}
func (m *LockOutpointResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_LockOutpointResponse.DiscardUnknown(m)
}

var xxx_messageInfo_LockOutpointResponse proto.InternalMessageInfo

type UnlockOutpointRequest struct {
	Hash                 []byte   `protobuf:"bytes,1,opt,name=hash,proto3" json:"hash,omitempty"`
	Index                uint32   `protobuf:"varint,2,opt,name=index,proto3" json:"index,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *UnlockOutpointRequest) Reset()         { *m = UnlockOutpointRequest{} }
func (m *UnlockOutpointRequest) String() string { return proto.CompactTextString(m) }
func (*UnlockOutpointRequest) ProtoMessage()    {}
func (*UnlockOutpointRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_2d4b5db5d7eac1f0, []int{7}
}

func (m *UnlockOutpointRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_UnlockOutpointRequest.Unmarshal(m, b)
}
func (m *UnlockOutpointRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_UnlockOutpointRequest.Marshal(b, m, deterministic)
}
func (m *UnlockOutpointRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UnlockOutpointRequest.Merge(m, src)
}
func (m *UnlockOutpointRequest) XXX_Size() int {
	return xxx_messageInfo_UnlockOutpointRequest.Size(m)
}
func (m *UnlockOutpointRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_UnlockOutpointRequest.DiscardUnknown(m)
}

var xxx_messageInfo_UnlockOutpointRequest proto.InternalMessageInfo

func (m *UnlockOutpointRequest) GetHash() []byte {
	if m != nil {
		return m.Hash
	}
	return nil
}

func (m *UnlockOutpointRequest) GetIndex() uint32 {
	if m != nil {
		return m.Index
	}
	return 0
}

type UnlockOutpointResponse struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *UnlockOutpointResponse) Reset()         { *m = UnlockOutpointResponse{} }
func (m *UnlockOutpointResponse) String() string { return proto.CompactTextString(m) }
func (*UnlockOutpointResponse) ProtoMessage()    {}
func (*UnlockOutpointResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_2d4b5db5d7eac1f0, []int{8}
}

func (m *UnlockOutpointResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_UnlockOutpointResponse.Unmarshal(m, b)
}
func (m *UnlockOutpointResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_UnlockOutpointResponse.Marshal(b, m, deterministic)
}
func (m *UnlockOutpointResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_UnlockOutpointResponse.Merge(m, src)
}
func (m *UnlockOutpointResponse) XXX_Size() int {
	return xxx_messageInfo_UnlockOutpointResponse.Size(m)
}
func (m *UnlockOutpointResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_UnlockOutpointResponse.DiscardUnknown(m)
}

var xxx_messageInfo_UnlockOutpointResponse proto.InternalMessageInfo

func init() {
	proto.RegisterType((*SignMessageRequest)(nil), "SignMessageRequest")
	proto.RegisterType((*SignMessageResponse)(nil), "SignMessageResponse")
	proto.RegisterType((*ListUnspentWitnessRequest)(nil), "ListUnspentWitnessRequest")
	proto.RegisterType((*ListUnspentWitnessResponse)(nil), "ListUnspentWitnessResponse")
	proto.RegisterType((*Utxo)(nil), "Utxo")
	proto.RegisterType((*LockOutpointRequest)(nil), "LockOutpointRequest")
	proto.RegisterType((*LockOutpointResponse)(nil), "LockOutpointResponse")
	proto.RegisterType((*UnlockOutpointRequest)(nil), "UnlockOutpointRequest")
	proto.RegisterType((*UnlockOutpointResponse)(nil), "UnlockOutpointResponse")
}

func init() { proto.RegisterFile("pine.proto", fileDescriptor_2d4b5db5d7eac1f0) }

var fileDescriptor_2d4b5db5d7eac1f0 = []byte{
	// 442 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x53, 0x4d, 0x6f, 0x13, 0x31,
	0x10, 0xcd, 0xc7, 0x6e, 0x81, 0x49, 0x03, 0x68, 0x92, 0x86, 0x65, 0xcb, 0xa1, 0xb2, 0x38, 0x44,
	0x1c, 0x7c, 0x68, 0x4f, 0x20, 0x21, 0x84, 0x7a, 0x41, 0x22, 0xa8, 0x68, 0x4b, 0xc4, 0xd9, 0xdd,
	0x98, 0xd4, 0x6a, 0x62, 0x9b, 0x1d, 0x6f, 0x95, 0xfe, 0x12, 0xfe, 0x0d, 0xbf, 0x0d, 0xad, 0xdd,
	0xd0, 0x6c, 0xb2, 0x39, 0xf5, 0xe6, 0x79, 0x9e, 0x7d, 0x7e, 0xf3, 0xe6, 0x2d, 0x80, 0x55, 0x5a,
	0x72, 0x5b, 0x18, 0x67, 0xd8, 0x04, 0xf0, 0x52, 0xcd, 0xf5, 0x37, 0x49, 0x24, 0xe6, 0x32, 0x93,
	0xbf, 0x4b, 0x49, 0x0e, 0x13, 0x78, 0xb2, 0x0c, 0x48, 0xd2, 0x3e, 0x69, 0x8f, 0x0f, 0xb3, 0x75,
	0x89, 0x6f, 0xe0, 0x99, 0x2d, 0xaf, 0x16, 0x2a, 0xff, 0x2a, 0xef, 0x92, 0x8e, 0xbf, 0x7b, 0x00,
	0xd8, 0x19, 0x0c, 0x6a, 0x6c, 0x64, 0x8d, 0x26, 0xff, 0x11, 0xa9, 0xb9, 0x16, 0xae, 0x2c, 0xd6,
	0x84, 0x0f, 0x00, 0x23, 0x78, 0x3d, 0x51, 0xe4, 0xa6, 0x9a, 0xac, 0xd4, 0xee, 0xa7, 0x72, 0x5a,
	0x12, 0xad, 0x95, 0xbc, 0x83, 0x97, 0x4b, 0xa5, 0xcf, 0x8d, 0xfe, 0xa5, 0x8a, 0xa5, 0x70, 0xca,
	0x68, 0xf2, 0x0c, 0x71, 0xb6, 0x83, 0xfb, 0x5e, 0xb1, 0xaa, 0xf7, 0x76, 0xee, 0x7b, 0xb7, 0x70,
	0xf6, 0x1e, 0xd2, 0xa6, 0x47, 0xef, 0x05, 0x1f, 0x43, 0x5c, 0xba, 0x95, 0xa9, 0x9e, 0xea, 0x8e,
	0x7b, 0xa7, 0x31, 0x9f, 0xba, 0x95, 0xc9, 0x02, 0xc6, 0xfe, 0xb6, 0x21, 0xaa, 0x6a, 0x3c, 0x81,
	0x9e, 0x98, 0xcd, 0x0a, 0x49, 0xf4, 0xe3, 0xce, 0x86, 0xc1, 0xfa, 0xd9, 0x26, 0x84, 0x43, 0x88,
	0x6f, 0xc5, 0xa2, 0x94, 0x5e, 0x46, 0x37, 0x0b, 0x05, 0xbe, 0x85, 0x7e, 0x5e, 0x13, 0xd9, 0xf5,
	0xb7, 0x75, 0x10, 0x53, 0x78, 0x6a, 0x6f, 0x2e, 0xf3, 0x42, 0x59, 0x97, 0x44, 0xde, 0xb3, 0xff,
	0x35, 0x8e, 0xe1, 0x85, 0x2b, 0x84, 0x26, 0x91, 0x57, 0xbd, 0x5f, 0x04, 0x5d, 0x27, 0xb1, 0x6f,
	0xd9, 0x86, 0x11, 0x21, 0xba, 0x35, 0xa5, 0x4b, 0x0e, 0xbc, 0x38, 0x7f, 0x66, 0x9f, 0x60, 0x30,
	0x31, 0xf9, 0xcd, 0x45, 0xe9, 0xac, 0x51, 0xda, 0xad, 0xad, 0x46, 0x88, 0xae, 0x2b, 0xa6, 0xb0,
	0x20, 0x7f, 0xae, 0x06, 0x50, 0x7a, 0x26, 0x57, 0x7e, 0x80, 0x7e, 0x16, 0x0a, 0x36, 0x82, 0x61,
	0x9d, 0x20, 0xd8, 0xc6, 0x3e, 0xc3, 0xd1, 0x54, 0x2f, 0x1e, 0x45, 0x9d, 0xc0, 0x68, 0x9b, 0x22,
	0x90, 0x9f, 0xfe, 0xe9, 0x40, 0xf4, 0x5d, 0x69, 0x89, 0x1f, 0xa0, 0xb7, 0x11, 0x32, 0x1c, 0xf0,
	0xdd, 0x00, 0xa7, 0x43, 0xde, 0x90, 0x43, 0xd6, 0xc2, 0x0b, 0xc0, 0xdd, 0xb5, 0x63, 0xca, 0xf7,
	0x06, 0x30, 0x3d, 0xe6, 0xfb, 0x73, 0xc2, 0x5a, 0xf8, 0x11, 0x0e, 0x37, 0xad, 0xc0, 0x21, 0x6f,
	0xb0, 0x36, 0x3d, 0xe2, 0x8d, 0x7e, 0xb5, 0xf0, 0x1c, 0x9e, 0xd7, 0xc7, 0xc5, 0x11, 0x6f, 0xb4,
	0x30, 0x7d, 0xc5, 0x9b, 0x7d, 0x61, 0xad, 0xab, 0x03, 0xff, 0x2b, 0x9f, 0xfd, 0x0b, 0x00, 0x00,
	0xff, 0xff, 0x56, 0x29, 0x44, 0x23, 0xd8, 0x03, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// PineClient is the client API for Pine service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type PineClient interface {
	SignMessage(ctx context.Context, in *SignMessageRequest, opts ...grpc.CallOption) (*SignMessageResponse, error)
	ListUnspentWitness(ctx context.Context, in *ListUnspentWitnessRequest, opts ...grpc.CallOption) (*ListUnspentWitnessResponse, error)
	// LockOutpoint marks an unspent transaction output as reserved excluding
	// it from coin selection.
	LockOutpoint(ctx context.Context, in *LockOutpointRequest, opts ...grpc.CallOption) (*LockOutpointResponse, error)
	// UnlockOutpoint unmarks an unspent transaction output as reserved making
	// it eligible for coin selection.
	UnlockOutpoint(ctx context.Context, in *UnlockOutpointRequest, opts ...grpc.CallOption) (*UnlockOutpointResponse, error)
}

type pineClient struct {
	cc *grpc.ClientConn
}

func NewPineClient(cc *grpc.ClientConn) PineClient {
	return &pineClient{cc}
}

func (c *pineClient) SignMessage(ctx context.Context, in *SignMessageRequest, opts ...grpc.CallOption) (*SignMessageResponse, error) {
	out := new(SignMessageResponse)
	err := c.cc.Invoke(ctx, "/Pine/SignMessage", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pineClient) ListUnspentWitness(ctx context.Context, in *ListUnspentWitnessRequest, opts ...grpc.CallOption) (*ListUnspentWitnessResponse, error) {
	out := new(ListUnspentWitnessResponse)
	err := c.cc.Invoke(ctx, "/Pine/ListUnspentWitness", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pineClient) LockOutpoint(ctx context.Context, in *LockOutpointRequest, opts ...grpc.CallOption) (*LockOutpointResponse, error) {
	out := new(LockOutpointResponse)
	err := c.cc.Invoke(ctx, "/Pine/LockOutpoint", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *pineClient) UnlockOutpoint(ctx context.Context, in *UnlockOutpointRequest, opts ...grpc.CallOption) (*UnlockOutpointResponse, error) {
	out := new(UnlockOutpointResponse)
	err := c.cc.Invoke(ctx, "/Pine/UnlockOutpoint", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PineServer is the server API for Pine service.
type PineServer interface {
	SignMessage(context.Context, *SignMessageRequest) (*SignMessageResponse, error)
	ListUnspentWitness(context.Context, *ListUnspentWitnessRequest) (*ListUnspentWitnessResponse, error)
	// LockOutpoint marks an unspent transaction output as reserved excluding
	// it from coin selection.
	LockOutpoint(context.Context, *LockOutpointRequest) (*LockOutpointResponse, error)
	// UnlockOutpoint unmarks an unspent transaction output as reserved making
	// it eligible for coin selection.
	UnlockOutpoint(context.Context, *UnlockOutpointRequest) (*UnlockOutpointResponse, error)
}

// UnimplementedPineServer can be embedded to have forward compatible implementations.
type UnimplementedPineServer struct {
}

func (*UnimplementedPineServer) SignMessage(ctx context.Context, req *SignMessageRequest) (*SignMessageResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SignMessage not implemented")
}
func (*UnimplementedPineServer) ListUnspentWitness(ctx context.Context, req *ListUnspentWitnessRequest) (*ListUnspentWitnessResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListUnspentWitness not implemented")
}
func (*UnimplementedPineServer) LockOutpoint(ctx context.Context, req *LockOutpointRequest) (*LockOutpointResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method LockOutpoint not implemented")
}
func (*UnimplementedPineServer) UnlockOutpoint(ctx context.Context, req *UnlockOutpointRequest) (*UnlockOutpointResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UnlockOutpoint not implemented")
}

func RegisterPineServer(s *grpc.Server, srv PineServer) {
	s.RegisterService(&_Pine_serviceDesc, srv)
}

func _Pine_SignMessage_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignMessageRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PineServer).SignMessage(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Pine/SignMessage",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PineServer).SignMessage(ctx, req.(*SignMessageRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Pine_ListUnspentWitness_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListUnspentWitnessRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PineServer).ListUnspentWitness(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Pine/ListUnspentWitness",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PineServer).ListUnspentWitness(ctx, req.(*ListUnspentWitnessRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Pine_LockOutpoint_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LockOutpointRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PineServer).LockOutpoint(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Pine/LockOutpoint",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PineServer).LockOutpoint(ctx, req.(*LockOutpointRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Pine_UnlockOutpoint_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UnlockOutpointRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(PineServer).UnlockOutpoint(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/Pine/UnlockOutpoint",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(PineServer).UnlockOutpoint(ctx, req.(*UnlockOutpointRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Pine_serviceDesc = grpc.ServiceDesc{
	ServiceName: "Pine",
	HandlerType: (*PineServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SignMessage",
			Handler:    _Pine_SignMessage_Handler,
		},
		{
			MethodName: "ListUnspentWitness",
			Handler:    _Pine_ListUnspentWitness_Handler,
		},
		{
			MethodName: "LockOutpoint",
			Handler:    _Pine_LockOutpoint_Handler,
		},
		{
			MethodName: "UnlockOutpoint",
			Handler:    _Pine_UnlockOutpoint_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "pine.proto",
}
