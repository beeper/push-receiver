// Code generated by protoc-gen-go. DO NOT EDIT.
// source: android_checkin.proto

package checkin_proto

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
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

// enum values correspond to the type of device.
// Used in the AndroidCheckinProto and Device proto.
type DeviceType int32

const (
	// Android Device
	DeviceType_DEVICE_ANDROID_OS DeviceType = 1
	// Apple IOS device
	DeviceType_DEVICE_IOS_OS DeviceType = 2
	// Chrome browser - Not Chrome OS.  No hardware records.
	DeviceType_DEVICE_CHROME_BROWSER DeviceType = 3
	// Chrome OS
	DeviceType_DEVICE_CHROME_OS DeviceType = 4
)

var DeviceType_name = map[int32]string{
	1: "DEVICE_ANDROID_OS",
	2: "DEVICE_IOS_OS",
	3: "DEVICE_CHROME_BROWSER",
	4: "DEVICE_CHROME_OS",
}

var DeviceType_value = map[string]int32{
	"DEVICE_ANDROID_OS":     1,
	"DEVICE_IOS_OS":         2,
	"DEVICE_CHROME_BROWSER": 3,
	"DEVICE_CHROME_OS":      4,
}

func (x DeviceType) Enum() *DeviceType {
	p := new(DeviceType)
	*p = x
	return p
}

func (x DeviceType) String() string {
	return proto.EnumName(DeviceType_name, int32(x))
}

func (x *DeviceType) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(DeviceType_value, data, "DeviceType")
	if err != nil {
		return err
	}
	*x = DeviceType(value)
	return nil
}

func (DeviceType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_7fda63b0cb1fbda4, []int{0}
}

type ChromeBuildProto_Platform int32

const (
	ChromeBuildProto_PLATFORM_WIN   ChromeBuildProto_Platform = 1
	ChromeBuildProto_PLATFORM_MAC   ChromeBuildProto_Platform = 2
	ChromeBuildProto_PLATFORM_LINUX ChromeBuildProto_Platform = 3
	ChromeBuildProto_PLATFORM_CROS  ChromeBuildProto_Platform = 4
	ChromeBuildProto_PLATFORM_IOS   ChromeBuildProto_Platform = 5
	// Just a placeholder. Likely don't need it due to the presence of the
	// Android GCM on phone/tablet devices.
	ChromeBuildProto_PLATFORM_ANDROID ChromeBuildProto_Platform = 6
)

var ChromeBuildProto_Platform_name = map[int32]string{
	1: "PLATFORM_WIN",
	2: "PLATFORM_MAC",
	3: "PLATFORM_LINUX",
	4: "PLATFORM_CROS",
	5: "PLATFORM_IOS",
	6: "PLATFORM_ANDROID",
}

var ChromeBuildProto_Platform_value = map[string]int32{
	"PLATFORM_WIN":     1,
	"PLATFORM_MAC":     2,
	"PLATFORM_LINUX":   3,
	"PLATFORM_CROS":    4,
	"PLATFORM_IOS":     5,
	"PLATFORM_ANDROID": 6,
}

func (x ChromeBuildProto_Platform) Enum() *ChromeBuildProto_Platform {
	p := new(ChromeBuildProto_Platform)
	*p = x
	return p
}

func (x ChromeBuildProto_Platform) String() string {
	return proto.EnumName(ChromeBuildProto_Platform_name, int32(x))
}

func (x *ChromeBuildProto_Platform) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(ChromeBuildProto_Platform_value, data, "ChromeBuildProto_Platform")
	if err != nil {
		return err
	}
	*x = ChromeBuildProto_Platform(value)
	return nil
}

func (ChromeBuildProto_Platform) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_7fda63b0cb1fbda4, []int{0, 0}
}

type ChromeBuildProto_Channel int32

const (
	ChromeBuildProto_CHANNEL_STABLE  ChromeBuildProto_Channel = 1
	ChromeBuildProto_CHANNEL_BETA    ChromeBuildProto_Channel = 2
	ChromeBuildProto_CHANNEL_DEV     ChromeBuildProto_Channel = 3
	ChromeBuildProto_CHANNEL_CANARY  ChromeBuildProto_Channel = 4
	ChromeBuildProto_CHANNEL_UNKNOWN ChromeBuildProto_Channel = 5
)

var ChromeBuildProto_Channel_name = map[int32]string{
	1: "CHANNEL_STABLE",
	2: "CHANNEL_BETA",
	3: "CHANNEL_DEV",
	4: "CHANNEL_CANARY",
	5: "CHANNEL_UNKNOWN",
}

var ChromeBuildProto_Channel_value = map[string]int32{
	"CHANNEL_STABLE":  1,
	"CHANNEL_BETA":    2,
	"CHANNEL_DEV":     3,
	"CHANNEL_CANARY":  4,
	"CHANNEL_UNKNOWN": 5,
}

func (x ChromeBuildProto_Channel) Enum() *ChromeBuildProto_Channel {
	p := new(ChromeBuildProto_Channel)
	*p = x
	return p
}

func (x ChromeBuildProto_Channel) String() string {
	return proto.EnumName(ChromeBuildProto_Channel_name, int32(x))
}

func (x *ChromeBuildProto_Channel) UnmarshalJSON(data []byte) error {
	value, err := proto.UnmarshalJSONEnum(ChromeBuildProto_Channel_value, data, "ChromeBuildProto_Channel")
	if err != nil {
		return err
	}
	*x = ChromeBuildProto_Channel(value)
	return nil
}

func (ChromeBuildProto_Channel) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_7fda63b0cb1fbda4, []int{0, 1}
}

// Build characteristics unique to the Chrome browser, and Chrome OS
type ChromeBuildProto struct {
	// The platform of the device.
	Platform *ChromeBuildProto_Platform `protobuf:"varint,1,opt,name=platform,enum=checkin_proto.ChromeBuildProto_Platform" json:"platform,omitempty"`
	// The Chrome instance's version.
	ChromeVersion *string `protobuf:"bytes,2,opt,name=chrome_version,json=chromeVersion" json:"chrome_version,omitempty"`
	// The Channel (build type) of Chrome.
	Channel              *ChromeBuildProto_Channel `protobuf:"varint,3,opt,name=channel,enum=checkin_proto.ChromeBuildProto_Channel" json:"channel,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                  `json:"-"`
	XXX_unrecognized     []byte                    `json:"-"`
	XXX_sizecache        int32                     `json:"-"`
}

func (m *ChromeBuildProto) Reset()         { *m = ChromeBuildProto{} }
func (m *ChromeBuildProto) String() string { return proto.CompactTextString(m) }
func (*ChromeBuildProto) ProtoMessage()    {}
func (*ChromeBuildProto) Descriptor() ([]byte, []int) {
	return fileDescriptor_7fda63b0cb1fbda4, []int{0}
}

func (m *ChromeBuildProto) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ChromeBuildProto.Unmarshal(m, b)
}
func (m *ChromeBuildProto) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ChromeBuildProto.Marshal(b, m, deterministic)
}
func (m *ChromeBuildProto) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ChromeBuildProto.Merge(m, src)
}
func (m *ChromeBuildProto) XXX_Size() int {
	return xxx_messageInfo_ChromeBuildProto.Size(m)
}
func (m *ChromeBuildProto) XXX_DiscardUnknown() {
	xxx_messageInfo_ChromeBuildProto.DiscardUnknown(m)
}

var xxx_messageInfo_ChromeBuildProto proto.InternalMessageInfo

func (m *ChromeBuildProto) GetPlatform() ChromeBuildProto_Platform {
	if m != nil && m.Platform != nil {
		return *m.Platform
	}
	return ChromeBuildProto_PLATFORM_WIN
}

func (m *ChromeBuildProto) GetChromeVersion() string {
	if m != nil && m.ChromeVersion != nil {
		return *m.ChromeVersion
	}
	return ""
}

func (m *ChromeBuildProto) GetChannel() ChromeBuildProto_Channel {
	if m != nil && m.Channel != nil {
		return *m.Channel
	}
	return ChromeBuildProto_CHANNEL_STABLE
}

// Information sent by the device in a "checkin" request.
type AndroidCheckinProto struct {
	// Miliseconds since the Unix epoch of the device's last successful checkin.
	LastCheckinMsec *int64 `protobuf:"varint,2,opt,name=last_checkin_msec,json=lastCheckinMsec" json:"last_checkin_msec,omitempty"`
	// The current MCC+MNC of the mobile device's current cell.
	CellOperator *string `protobuf:"bytes,6,opt,name=cell_operator,json=cellOperator" json:"cell_operator,omitempty"`
	// The MCC+MNC of the SIM card (different from operator if the
	// device is roaming, for instance).
	SimOperator *string `protobuf:"bytes,7,opt,name=sim_operator,json=simOperator" json:"sim_operator,omitempty"`
	// The device's current roaming state (reported starting in eclair builds).
	// Currently one of "{,not}mobile-{,not}roaming", if it is present at all.
	Roaming *string `protobuf:"bytes,8,opt,name=roaming" json:"roaming,omitempty"`
	// For devices supporting multiple user profiles (which may be
	// supported starting in jellybean), the ordinal number of the
	// profile that is checking in.  This is 0 for the primary profile
	// (which can't be changed without wiping the device), and 1,2,3,...
	// for additional profiles (which can be added and deleted freely).
	UserNumber *int32 `protobuf:"varint,9,opt,name=user_number,json=userNumber" json:"user_number,omitempty"`
	// Class of device.  Indicates the type of build proto
	// (IosBuildProto/ChromeBuildProto/AndroidBuildProto)
	// That is included in this proto
	Type *DeviceType `protobuf:"varint,12,opt,name=type,enum=checkin_proto.DeviceType,def=1" json:"type,omitempty"`
	// For devices running MCS on Chrome, build-specific characteristics
	// of the browser.  There are no hardware aspects (except for ChromeOS).
	// This will only be populated for Chrome builds/ChromeOS devices
	ChromeBuild          *ChromeBuildProto `protobuf:"bytes,13,opt,name=chrome_build,json=chromeBuild" json:"chrome_build,omitempty"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *AndroidCheckinProto) Reset()         { *m = AndroidCheckinProto{} }
func (m *AndroidCheckinProto) String() string { return proto.CompactTextString(m) }
func (*AndroidCheckinProto) ProtoMessage()    {}
func (*AndroidCheckinProto) Descriptor() ([]byte, []int) {
	return fileDescriptor_7fda63b0cb1fbda4, []int{1}
}

func (m *AndroidCheckinProto) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_AndroidCheckinProto.Unmarshal(m, b)
}
func (m *AndroidCheckinProto) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_AndroidCheckinProto.Marshal(b, m, deterministic)
}
func (m *AndroidCheckinProto) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AndroidCheckinProto.Merge(m, src)
}
func (m *AndroidCheckinProto) XXX_Size() int {
	return xxx_messageInfo_AndroidCheckinProto.Size(m)
}
func (m *AndroidCheckinProto) XXX_DiscardUnknown() {
	xxx_messageInfo_AndroidCheckinProto.DiscardUnknown(m)
}

var xxx_messageInfo_AndroidCheckinProto proto.InternalMessageInfo

const Default_AndroidCheckinProto_Type DeviceType = DeviceType_DEVICE_ANDROID_OS

func (m *AndroidCheckinProto) GetLastCheckinMsec() int64 {
	if m != nil && m.LastCheckinMsec != nil {
		return *m.LastCheckinMsec
	}
	return 0
}

func (m *AndroidCheckinProto) GetCellOperator() string {
	if m != nil && m.CellOperator != nil {
		return *m.CellOperator
	}
	return ""
}

func (m *AndroidCheckinProto) GetSimOperator() string {
	if m != nil && m.SimOperator != nil {
		return *m.SimOperator
	}
	return ""
}

func (m *AndroidCheckinProto) GetRoaming() string {
	if m != nil && m.Roaming != nil {
		return *m.Roaming
	}
	return ""
}

func (m *AndroidCheckinProto) GetUserNumber() int32 {
	if m != nil && m.UserNumber != nil {
		return *m.UserNumber
	}
	return 0
}

func (m *AndroidCheckinProto) GetType() DeviceType {
	if m != nil && m.Type != nil {
		return *m.Type
	}
	return Default_AndroidCheckinProto_Type
}

func (m *AndroidCheckinProto) GetChromeBuild() *ChromeBuildProto {
	if m != nil {
		return m.ChromeBuild
	}
	return nil
}

func init() {
	proto.RegisterEnum("checkin_proto.DeviceType", DeviceType_name, DeviceType_value)
	proto.RegisterEnum("checkin_proto.ChromeBuildProto_Platform", ChromeBuildProto_Platform_name, ChromeBuildProto_Platform_value)
	proto.RegisterEnum("checkin_proto.ChromeBuildProto_Channel", ChromeBuildProto_Channel_name, ChromeBuildProto_Channel_value)
	proto.RegisterType((*ChromeBuildProto)(nil), "checkin_proto.ChromeBuildProto")
	proto.RegisterType((*AndroidCheckinProto)(nil), "checkin_proto.AndroidCheckinProto")
}

func init() { proto.RegisterFile("android_checkin.proto", fileDescriptor_7fda63b0cb1fbda4) }

var fileDescriptor_7fda63b0cb1fbda4 = []byte{
	// 509 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x92, 0xcd, 0x6e, 0xda, 0x40,
	0x1c, 0xc4, 0x65, 0x1b, 0x02, 0xf9, 0xf3, 0xb5, 0x6c, 0x8a, 0xe4, 0x9c, 0x42, 0xa9, 0xaa, 0xa2,
	0x1c, 0x38, 0xe4, 0xd8, 0x53, 0xfd, 0x55, 0x61, 0x15, 0x6c, 0xb4, 0x26, 0xd0, 0x9e, 0x56, 0x8e,
	0xd9, 0x06, 0xab, 0xfe, 0x40, 0x6b, 0x88, 0x94, 0x43, 0xdf, 0xa8, 0x4f, 0xd2, 0xa7, 0xaa, 0xbc,
	0xb6, 0xa1, 0x24, 0x87, 0x1c, 0xf7, 0xb7, 0x33, 0x1e, 0x6b, 0x67, 0x60, 0xe0, 0x27, 0x1b, 0x9e,
	0x86, 0x1b, 0x1a, 0x6c, 0x59, 0xf0, 0x2b, 0x4c, 0x26, 0x3b, 0x9e, 0xee, 0x53, 0xdc, 0x29, 0x8f,
	0x54, 0x1c, 0x47, 0x7f, 0x14, 0x40, 0xc6, 0x96, 0xa7, 0x31, 0xd3, 0x0f, 0x61, 0xb4, 0x59, 0x08,
	0x8d, 0x09, 0xcd, 0x5d, 0xe4, 0xef, 0x7f, 0xa6, 0x3c, 0x56, 0xa5, 0xa1, 0x34, 0xee, 0xde, 0x8d,
	0x27, 0x67, 0xb6, 0xc9, 0x4b, 0xcb, 0x64, 0x51, 0xea, 0xc9, 0xd1, 0x89, 0x3f, 0x42, 0x37, 0x10,
	0x32, 0xfa, 0xc4, 0x78, 0x16, 0xa6, 0x89, 0x2a, 0x0f, 0xa5, 0xf1, 0x25, 0xe9, 0x14, 0x74, 0x55,
	0x40, 0xac, 0x41, 0x23, 0xd8, 0xfa, 0x49, 0xc2, 0x22, 0x55, 0x11, 0x59, 0x9f, 0xde, 0xca, 0x32,
	0x0a, 0x39, 0xa9, 0x7c, 0xa3, 0xdf, 0xd0, 0xac, 0xf2, 0x31, 0x82, 0xf6, 0x62, 0xa6, 0x2d, 0xbf,
	0xba, 0x64, 0x4e, 0xd7, 0xb6, 0x83, 0xa4, 0x33, 0x32, 0xd7, 0x0c, 0x24, 0x63, 0x0c, 0xdd, 0x23,
	0x99, 0xd9, 0xce, 0xfd, 0x77, 0xa4, 0xe0, 0x3e, 0x74, 0x8e, 0xcc, 0x20, 0xae, 0x87, 0x6a, 0x67,
	0x46, 0xdb, 0xf5, 0x50, 0x1d, 0xbf, 0x03, 0x74, 0x24, 0x9a, 0x63, 0x12, 0xd7, 0x36, 0xd1, 0xc5,
	0x28, 0x84, 0x46, 0xf9, 0x4b, 0xf9, 0x97, 0x8d, 0xa9, 0xe6, 0x38, 0xd6, 0x8c, 0x7a, 0x4b, 0x4d,
	0x9f, 0x59, 0x45, 0x7e, 0xc5, 0x74, 0x6b, 0xa9, 0x21, 0x19, 0xf7, 0xa0, 0x55, 0x11, 0xd3, 0x5a,
	0x21, 0xe5, 0x7f, 0x9b, 0xa1, 0x39, 0x1a, 0xf9, 0x81, 0x6a, 0xf8, 0x0a, 0x7a, 0x15, 0xbb, 0x77,
	0xbe, 0x39, 0xee, 0xda, 0x41, 0xf5, 0xd1, 0x5f, 0x19, 0xae, 0xb4, 0xa2, 0x57, 0xa3, 0x78, 0xa4,
	0xa2, 0xb1, 0x5b, 0xe8, 0x47, 0x7e, 0xb6, 0xaf, 0xba, 0xa6, 0x71, 0xc6, 0x02, 0xf1, 0xdc, 0x0a,
	0xe9, 0xe5, 0x17, 0xa5, 0x78, 0x9e, 0xb1, 0x00, 0x7f, 0x80, 0x4e, 0xc0, 0xa2, 0x88, 0xa6, 0x3b,
	0xc6, 0xfd, 0x7d, 0xca, 0xd5, 0x0b, 0x51, 0x4b, 0x3b, 0x87, 0x6e, 0xc9, 0xf0, 0x7b, 0x68, 0x67,
	0x61, 0x7c, 0xd2, 0x34, 0x84, 0xa6, 0x95, 0x85, 0xf1, 0x51, 0xa2, 0x42, 0x83, 0xa7, 0x7e, 0x1c,
	0x26, 0x8f, 0x6a, 0x53, 0xdc, 0x56, 0x47, 0x7c, 0x03, 0xad, 0x43, 0xc6, 0x38, 0x4d, 0x0e, 0xf1,
	0x03, 0xe3, 0xea, 0xe5, 0x50, 0x1a, 0xd7, 0x09, 0xe4, 0xc8, 0x11, 0x04, 0x7f, 0x81, 0xda, 0xfe,
	0x79, 0xc7, 0xd4, 0xb6, 0x28, 0xfc, 0xfa, 0x45, 0xe1, 0x26, 0x7b, 0x0a, 0x03, 0xb6, 0x7c, 0xde,
	0xb1, 0xcf, 0x7d, 0xd3, 0x5a, 0xd9, 0x86, 0x55, 0x3d, 0x36, 0x75, 0x3d, 0x22, 0x9c, 0x58, 0x87,
	0x76, 0x39, 0xae, 0x87, 0x7c, 0x18, 0x6a, 0x67, 0x28, 0x8d, 0x5b, 0x77, 0x37, 0x6f, 0x4c, 0x87,
	0xb4, 0x82, 0x13, 0xb9, 0x7d, 0x04, 0x38, 0x45, 0xe1, 0x01, 0xbc, 0x0e, 0x43, 0x52, 0xbe, 0x8b,
	0x12, 0xdb, 0xae, 0x97, 0x23, 0x19, 0x5f, 0xc3, 0xa0, 0x44, 0xc6, 0x94, 0xb8, 0x73, 0x8b, 0xea,
	0xc4, 0x5d, 0x7b, 0x16, 0x41, 0x4a, 0x3e, 0x90, 0xf3, 0xab, 0x7c, 0x48, 0xba, 0x3c, 0x55, 0xfe,
	0x05, 0x00, 0x00, 0xff, 0xff, 0x7c, 0xea, 0x4c, 0xe4, 0x8f, 0x03, 0x00, 0x00,
}