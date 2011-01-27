// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: chat_protocol.proto

package pl.edu.agh.mobile.adhoccom.chatprotocol;

public final class ChatProtocol {
  private ChatProtocol() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
  }
  public static final class ChatMessage extends
      com.google.protobuf.GeneratedMessage {
    // Use ChatMessage.newBuilder() to construct.
    private ChatMessage() {
      initFields();
    }
    private ChatMessage(boolean noInit) {}
    
    private static final ChatMessage defaultInstance;
    public static ChatMessage getDefaultInstance() {
      return defaultInstance;
    }
    
    public ChatMessage getDefaultInstanceForType() {
      return defaultInstance;
    }
    
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.internal_static_pl_edu_agh_mobile_adhoccom_chatprotocol_ChatMessage_descriptor;
    }
    
    protected com.google.protobuf.GeneratedMessage.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.internal_static_pl_edu_agh_mobile_adhoccom_chatprotocol_ChatMessage_fieldAccessorTable;
    }
    
    // required bytes body = 1;
    public static final int BODY_FIELD_NUMBER = 1;
    private boolean hasBody;
    private com.google.protobuf.ByteString body_ = com.google.protobuf.ByteString.EMPTY;
    public boolean hasBody() { return hasBody; }
    public com.google.protobuf.ByteString getBody() { return body_; }
    
    // required string sender = 2;
    public static final int SENDER_FIELD_NUMBER = 2;
    private boolean hasSender;
    private java.lang.String sender_ = "";
    public boolean hasSender() { return hasSender; }
    public java.lang.String getSender() { return sender_; }
    
    // required int32 date = 3;
    public static final int DATE_FIELD_NUMBER = 3;
    private boolean hasDate;
    private int date_ = 0;
    public boolean hasDate() { return hasDate; }
    public int getDate() { return date_; }
    
    // required string group_name = 4;
    public static final int GROUP_NAME_FIELD_NUMBER = 4;
    private boolean hasGroupName;
    private java.lang.String groupName_ = "";
    public boolean hasGroupName() { return hasGroupName; }
    public java.lang.String getGroupName() { return groupName_; }
    
    // optional bytes group_chalenge = 5;
    public static final int GROUP_CHALENGE_FIELD_NUMBER = 5;
    private boolean hasGroupChalenge;
    private com.google.protobuf.ByteString groupChalenge_ = com.google.protobuf.ByteString.EMPTY;
    public boolean hasGroupChalenge() { return hasGroupChalenge; }
    public com.google.protobuf.ByteString getGroupChalenge() { return groupChalenge_; }
    
    private void initFields() {
    }
    public final boolean isInitialized() {
      if (!hasBody) return false;
      if (!hasSender) return false;
      if (!hasDate) return false;
      if (!hasGroupName) return false;
      return true;
    }
    
    public void writeTo(com.google.protobuf.CodedOutputStream output)
                        throws java.io.IOException {
      getSerializedSize();
      if (hasBody()) {
        output.writeBytes(1, getBody());
      }
      if (hasSender()) {
        output.writeString(2, getSender());
      }
      if (hasDate()) {
        output.writeInt32(3, getDate());
      }
      if (hasGroupName()) {
        output.writeString(4, getGroupName());
      }
      if (hasGroupChalenge()) {
        output.writeBytes(5, getGroupChalenge());
      }
      getUnknownFields().writeTo(output);
    }
    
    private int memoizedSerializedSize = -1;
    public int getSerializedSize() {
      int size = memoizedSerializedSize;
      if (size != -1) return size;
    
      size = 0;
      if (hasBody()) {
        size += com.google.protobuf.CodedOutputStream
          .computeBytesSize(1, getBody());
      }
      if (hasSender()) {
        size += com.google.protobuf.CodedOutputStream
          .computeStringSize(2, getSender());
      }
      if (hasDate()) {
        size += com.google.protobuf.CodedOutputStream
          .computeInt32Size(3, getDate());
      }
      if (hasGroupName()) {
        size += com.google.protobuf.CodedOutputStream
          .computeStringSize(4, getGroupName());
      }
      if (hasGroupChalenge()) {
        size += com.google.protobuf.CodedOutputStream
          .computeBytesSize(5, getGroupChalenge());
      }
      size += getUnknownFields().getSerializedSize();
      memoizedSerializedSize = size;
      return size;
    }
    
    public static pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage parseFrom(
        com.google.protobuf.ByteString data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return newBuilder().mergeFrom(data).buildParsed();
    }
    public static pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage parseFrom(
        com.google.protobuf.ByteString data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return newBuilder().mergeFrom(data, extensionRegistry)
               .buildParsed();
    }
    public static pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage parseFrom(byte[] data)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return newBuilder().mergeFrom(data).buildParsed();
    }
    public static pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage parseFrom(
        byte[] data,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return newBuilder().mergeFrom(data, extensionRegistry)
               .buildParsed();
    }
    public static pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage parseFrom(java.io.InputStream input)
        throws java.io.IOException {
      return newBuilder().mergeFrom(input).buildParsed();
    }
    public static pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage parseFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return newBuilder().mergeFrom(input, extensionRegistry)
               .buildParsed();
    }
    public static pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage parseDelimitedFrom(java.io.InputStream input)
        throws java.io.IOException {
      Builder builder = newBuilder();
      if (builder.mergeDelimitedFrom(input)) {
        return builder.buildParsed();
      } else {
        return null;
      }
    }
    public static pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage parseDelimitedFrom(
        java.io.InputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      Builder builder = newBuilder();
      if (builder.mergeDelimitedFrom(input, extensionRegistry)) {
        return builder.buildParsed();
      } else {
        return null;
      }
    }
    public static pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage parseFrom(
        com.google.protobuf.CodedInputStream input)
        throws java.io.IOException {
      return newBuilder().mergeFrom(input).buildParsed();
    }
    public static pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage parseFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      return newBuilder().mergeFrom(input, extensionRegistry)
               .buildParsed();
    }
    
    public static Builder newBuilder() { return Builder.create(); }
    public Builder newBuilderForType() { return newBuilder(); }
    public static Builder newBuilder(pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage prototype) {
      return newBuilder().mergeFrom(prototype);
    }
    public Builder toBuilder() { return newBuilder(this); }
    
    public static final class Builder extends
        com.google.protobuf.GeneratedMessage.Builder<Builder> {
      private pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage result;
      
      // Construct using pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage.newBuilder()
      private Builder() {}
      
      private static Builder create() {
        Builder builder = new Builder();
        builder.result = new pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage();
        return builder;
      }
      
      protected pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage internalGetResult() {
        return result;
      }
      
      public Builder clear() {
        if (result == null) {
          throw new IllegalStateException(
            "Cannot call clear() after build().");
        }
        result = new pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage();
        return this;
      }
      
      public Builder clone() {
        return create().mergeFrom(result);
      }
      
      public com.google.protobuf.Descriptors.Descriptor
          getDescriptorForType() {
        return pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage.getDescriptor();
      }
      
      public pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage getDefaultInstanceForType() {
        return pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage.getDefaultInstance();
      }
      
      public boolean isInitialized() {
        return result.isInitialized();
      }
      public pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage build() {
        if (result != null && !isInitialized()) {
          throw newUninitializedMessageException(result);
        }
        return buildPartial();
      }
      
      private pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage buildParsed()
          throws com.google.protobuf.InvalidProtocolBufferException {
        if (!isInitialized()) {
          throw newUninitializedMessageException(
            result).asInvalidProtocolBufferException();
        }
        return buildPartial();
      }
      
      public pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage buildPartial() {
        if (result == null) {
          throw new IllegalStateException(
            "build() has already been called on this Builder.");
        }
        pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage returnMe = result;
        result = null;
        return returnMe;
      }
      
      public Builder mergeFrom(com.google.protobuf.Message other) {
        if (other instanceof pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage) {
          return mergeFrom((pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage)other);
        } else {
          super.mergeFrom(other);
          return this;
        }
      }
      
      public Builder mergeFrom(pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage other) {
        if (other == pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage.getDefaultInstance()) return this;
        if (other.hasBody()) {
          setBody(other.getBody());
        }
        if (other.hasSender()) {
          setSender(other.getSender());
        }
        if (other.hasDate()) {
          setDate(other.getDate());
        }
        if (other.hasGroupName()) {
          setGroupName(other.getGroupName());
        }
        if (other.hasGroupChalenge()) {
          setGroupChalenge(other.getGroupChalenge());
        }
        this.mergeUnknownFields(other.getUnknownFields());
        return this;
      }
      
      public Builder mergeFrom(
          com.google.protobuf.CodedInputStream input,
          com.google.protobuf.ExtensionRegistryLite extensionRegistry)
          throws java.io.IOException {
        com.google.protobuf.UnknownFieldSet.Builder unknownFields =
          com.google.protobuf.UnknownFieldSet.newBuilder(
            this.getUnknownFields());
        while (true) {
          int tag = input.readTag();
          switch (tag) {
            case 0:
              this.setUnknownFields(unknownFields.build());
              return this;
            default: {
              if (!parseUnknownField(input, unknownFields,
                                     extensionRegistry, tag)) {
                this.setUnknownFields(unknownFields.build());
                return this;
              }
              break;
            }
            case 10: {
              setBody(input.readBytes());
              break;
            }
            case 18: {
              setSender(input.readString());
              break;
            }
            case 24: {
              setDate(input.readInt32());
              break;
            }
            case 34: {
              setGroupName(input.readString());
              break;
            }
            case 42: {
              setGroupChalenge(input.readBytes());
              break;
            }
          }
        }
      }
      
      
      // required bytes body = 1;
      public boolean hasBody() {
        return result.hasBody();
      }
      public com.google.protobuf.ByteString getBody() {
        return result.getBody();
      }
      public Builder setBody(com.google.protobuf.ByteString value) {
        if (value == null) {
    throw new NullPointerException();
  }
  result.hasBody = true;
        result.body_ = value;
        return this;
      }
      public Builder clearBody() {
        result.hasBody = false;
        result.body_ = getDefaultInstance().getBody();
        return this;
      }
      
      // required string sender = 2;
      public boolean hasSender() {
        return result.hasSender();
      }
      public java.lang.String getSender() {
        return result.getSender();
      }
      public Builder setSender(java.lang.String value) {
        if (value == null) {
    throw new NullPointerException();
  }
  result.hasSender = true;
        result.sender_ = value;
        return this;
      }
      public Builder clearSender() {
        result.hasSender = false;
        result.sender_ = getDefaultInstance().getSender();
        return this;
      }
      
      // required int32 date = 3;
      public boolean hasDate() {
        return result.hasDate();
      }
      public int getDate() {
        return result.getDate();
      }
      public Builder setDate(int value) {
        result.hasDate = true;
        result.date_ = value;
        return this;
      }
      public Builder clearDate() {
        result.hasDate = false;
        result.date_ = 0;
        return this;
      }
      
      // required string group_name = 4;
      public boolean hasGroupName() {
        return result.hasGroupName();
      }
      public java.lang.String getGroupName() {
        return result.getGroupName();
      }
      public Builder setGroupName(java.lang.String value) {
        if (value == null) {
    throw new NullPointerException();
  }
  result.hasGroupName = true;
        result.groupName_ = value;
        return this;
      }
      public Builder clearGroupName() {
        result.hasGroupName = false;
        result.groupName_ = getDefaultInstance().getGroupName();
        return this;
      }
      
      // optional bytes group_chalenge = 5;
      public boolean hasGroupChalenge() {
        return result.hasGroupChalenge();
      }
      public com.google.protobuf.ByteString getGroupChalenge() {
        return result.getGroupChalenge();
      }
      public Builder setGroupChalenge(com.google.protobuf.ByteString value) {
        if (value == null) {
    throw new NullPointerException();
  }
  result.hasGroupChalenge = true;
        result.groupChalenge_ = value;
        return this;
      }
      public Builder clearGroupChalenge() {
        result.hasGroupChalenge = false;
        result.groupChalenge_ = getDefaultInstance().getGroupChalenge();
        return this;
      }
      
      // @@protoc_insertion_point(builder_scope:pl.edu.agh.mobile.adhoccom.chatprotocol.ChatMessage)
    }
    
    static {
      defaultInstance = new ChatMessage(true);
      pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.internalForceInit();
      defaultInstance.initFields();
    }
    
    // @@protoc_insertion_point(class_scope:pl.edu.agh.mobile.adhoccom.chatprotocol.ChatMessage)
  }
  
  private static com.google.protobuf.Descriptors.Descriptor
    internal_static_pl_edu_agh_mobile_adhoccom_chatprotocol_ChatMessage_descriptor;
  private static
    com.google.protobuf.GeneratedMessage.FieldAccessorTable
      internal_static_pl_edu_agh_mobile_adhoccom_chatprotocol_ChatMessage_fieldAccessorTable;
  
  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n\023chat_protocol.proto\022\'pl.edu.agh.mobile" +
      ".adhoccom.chatprotocol\"e\n\013ChatMessage\022\014\n" +
      "\004body\030\001 \002(\014\022\016\n\006sender\030\002 \002(\t\022\014\n\004date\030\003 \002(" +
      "\005\022\022\n\ngroup_name\030\004 \002(\t\022\026\n\016group_chalenge\030" +
      "\005 \001(\014"
    };
    com.google.protobuf.Descriptors.FileDescriptor.InternalDescriptorAssigner assigner =
      new com.google.protobuf.Descriptors.FileDescriptor.InternalDescriptorAssigner() {
        public com.google.protobuf.ExtensionRegistry assignDescriptors(
            com.google.protobuf.Descriptors.FileDescriptor root) {
          descriptor = root;
          internal_static_pl_edu_agh_mobile_adhoccom_chatprotocol_ChatMessage_descriptor =
            getDescriptor().getMessageTypes().get(0);
          internal_static_pl_edu_agh_mobile_adhoccom_chatprotocol_ChatMessage_fieldAccessorTable = new
            com.google.protobuf.GeneratedMessage.FieldAccessorTable(
              internal_static_pl_edu_agh_mobile_adhoccom_chatprotocol_ChatMessage_descriptor,
              new java.lang.String[] { "Body", "Sender", "Date", "GroupName", "GroupChalenge", },
              pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage.class,
              pl.edu.agh.mobile.adhoccom.chatprotocol.ChatProtocol.ChatMessage.Builder.class);
          return null;
        }
      };
    com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
        }, assigner);
  }
  
  public static void internalForceInit() {}
  
  // @@protoc_insertion_point(outer_class_scope)
}
