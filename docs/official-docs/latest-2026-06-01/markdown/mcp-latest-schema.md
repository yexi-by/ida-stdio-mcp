# MCP schema

- 官方来源：https://modelcontextprotocol.io/specification/2025-11-25/schema.md

> ## Documentation Index
> Fetch the complete documentation index at: https://modelcontextprotocol.io/llms.txt
> Use this file to discover all available pages before exploring further.

# Schema Reference

## JSON-RPC

### `JSONRPCErrorResponse`

interface JSONRPCErrorResponse \{
jsonrpc: "2.0";
id?: RequestId;
error: Error;
}A response to a request that indicates an error occurred. jsonrpc: "2.0"id?: RequestIderror: Error

### `JSONRPCMessage`

JSONRPCMessage: JSONRPCRequest | JSONRPCNotification | JSONRPCResponseRefers to any valid JSON-RPC object that can be decoded off the wire, or encoded to be sent.

### `JSONRPCNotification`

interface JSONRPCNotification \{
method: string;
params?: \{ \[key: string]: any };
jsonrpc: "2.0";
}A notification which does not expect a response. method: stringInherited from Notification.methodparams?: \{ \[key: string]: any }Inherited from Notification.paramsjsonrpc: "2.0"

### `JSONRPCRequest`

interface JSONRPCRequest \{
method: string;
params?: \{ \[key: string]: any };
jsonrpc: "2.0";
id: RequestId;
}A request that expects a response. method: stringInherited from Request.methodparams?: \{ \[key: string]: any }Inherited from Request.paramsjsonrpc: "2.0"id: RequestId

### `JSONRPCResponse`

JSONRPCResponse: JSONRPCResultResponse | JSONRPCErrorResponseA response to a request, containing either the result or error.

### `JSONRPCResultResponse`

interface JSONRPCResultResponse \{
jsonrpc: "2.0";
id: RequestId;
result: Result;
}A successful (non-error) response to a request. jsonrpc: "2.0"id: RequestIdresult: Result

## Common Types

### `Annotations`

interface Annotations \{
audience?: Role\[];
priority?: number;
lastModified?: string;
}Optional annotations for the client. The client can use annotations to inform how objects are used or displayed audience?: Role\[]Describes who the intended audience of this object or data is.

It can include multiple entries to indicate content useful for multiple audiences (e.g., \["user", "assistant"]). priority?: numberDescribes how important this data is for operating the server.

A value of 1 means "most important," and indicates that the data is
effectively required, while 0 means "least important," and indicates that
the data is entirely optional. lastModified?: stringThe moment the resource was last modified, as an ISO 8601 formatted string.

Should be an ISO 8601 formatted string (e.g., "2025-01-12T15:00:58Z").

Examples: last activity timestamp in an open file, timestamp when the resource
was attached, etc.

### `Cursor`

Cursor: stringAn opaque token used to represent a cursor for pagination.

### `EmptyResult`

EmptyResult: ResultA response that indicates success but carries no data.

### `Error`

interface Error \{
code: number;
message: string;
data?: unknown;
}code: numberThe error type that occurred. message: stringA short description of the error. The message SHOULD be limited to a concise single sentence. data?: unknownAdditional information about the error. The value of this member is defined by the sender (e.g. detailed error information, nested errors etc.).

### `Icon`

interface Icon \{
src: string;
mimeType?: string;
sizes?: string\[];
theme?: "light" | "dark";
}An optionally-sized icon that can be displayed in a user interface. src: stringA standard URI pointing to an icon resource. May be an HTTP/HTTPS URL or a data: URI with Base64-encoded image data.

Consumers SHOULD takes steps to ensure URLs serving icons are from the
same domain as the client/server or a trusted domain.

Consumers SHOULD take appropriate precautions when consuming SVGs as they can contain
executable JavaScript. mimeType?: stringOptional MIME type override if the source MIME type is missing or generic.
For example: "image/png", "image/jpeg", or "image/svg+xml". sizes?: string\[]Optional array of strings that specify sizes at which the icon can be used.
Each string should be in WxH format (e.g., "48x48", "96x96") or "any" for scalable formats like SVG.

If not provided, the client should assume that the icon can be used at any size. theme?: "light" | "dark"Optional specifier for the theme this icon is designed for. light indicates
the icon is designed to be used with a light background, and dark indicates
the icon is designed to be used with a dark background.

If not provided, the client should assume the icon can be used with any theme.

### `LoggingLevel`

LoggingLevel:
| "debug"
| "info"
| "notice"
| "warning"
| "error"
| "critical"
| "alert"
| "emergency"The severity of a log message.

These map to syslog message severities, as specified in RFC-5424: [https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.1](https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.1)

### `ProgressToken`

ProgressToken: string | numberA progress token, used to associate progress notifications with the original request.

### `RequestId`

RequestId: string | numberA uniquely identifying ID for a request in JSON-RPC.

### `Result`

interface Result \{
\_meta?: \{ \[key: string]: unknown };
\[key: string]: unknown;
}\_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage.

### `Role`

Role: "user" | "assistant"The sender or recipient of messages and data in a conversation.

## Content

### `AudioContent`

interface AudioContent \{
type: "audio";
data: string;
mimeType: string;
annotations?: Annotations;
\_meta?: \{ \[key: string]: unknown };
}Audio provided to or from an LLM. type: "audio"data: stringThe base64-encoded audio data. mimeType: stringThe MIME type of the audio. Different providers may support different audio types. annotations?: AnnotationsOptional annotations for the client. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage.

### `BlobResourceContents`

interface BlobResourceContents \{
uri: string;
mimeType?: string;
\_meta?: \{ \[key: string]: unknown };
blob: string;
}uri: stringThe URI of this resource. Inherited from ResourceContents.urimimeType?: stringThe MIME type of this resource, if known. Inherited from ResourceContents.mimeType\_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from ResourceContents.\_metablob: stringA base64-encoded string representing the binary data of the item.

### `ContentBlock`

ContentBlock:
| TextContent
| ImageContent
| AudioContent
| ResourceLink
| EmbeddedResource

### `EmbeddedResource`

interface EmbeddedResource \{
type: "resource";
resource: TextResourceContents | BlobResourceContents;
annotations?: Annotations;
\_meta?: \{ \[key: string]: unknown };
}The contents of a resource, embedded into a prompt or tool call result.

It is up to the client how best to render embedded resources for the benefit
of the LLM and/or the user. type: "resource"resource: TextResourceContents | BlobResourceContentsannotations?: AnnotationsOptional annotations for the client. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage.

### `ImageContent`

interface ImageContent \{
type: "image";
data: string;
mimeType: string;
annotations?: Annotations;
\_meta?: \{ \[key: string]: unknown };
}An image provided to or from an LLM. type: "image"data: stringThe base64-encoded image data. mimeType: stringThe MIME type of the image. Different providers may support different image types. annotations?: AnnotationsOptional annotations for the client. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage.

### `ResourceLink`

interface ResourceLink \{
icons?: Icon\[];
name: string;
title?: string;
uri: string;
description?: string;
mimeType?: string;
annotations?: Annotations;
size?: number;
\_meta?: \{ \[key: string]: unknown };
type: "resource\_link";
}A resource that the server is capable of reading, included in a prompt or tool call result.

Note: resource links returned by tools are not guaranteed to appear in the results of resources/list requests. icons?: Icon\[]Optional set of sized icons that the client can display in a user interface.

Clients that support rendering icons MUST support at least the following MIME types: - image/png - PNG images (safe, universal compatibility)
- image/jpeg (and image/jpg) - JPEG images (safe, universal compatibility) Clients that support rendering icons SHOULD also support: - image/svg+xml - SVG images (scalable but requires security precautions)
- image/webp - WebP images (modern, efficient format) Inherited from Resource.iconsname: stringIntended for programmatic or logical use, but used as a display name in past specs or fallback (if title isn't present). Inherited from Resource.nametitle?: stringIntended for UI and end-user contexts — optimized to be human-readable and easily understood,
even by those unfamiliar with domain-specific terminology.

If not provided, the name should be used for display (except for Tool,
where annotations.title should be given precedence over using name,
if present). Inherited from Resource.titleuri: stringThe URI of this resource. Inherited from Resource.uridescription?: stringA description of what this resource represents.

This can be used by clients to improve the LLM's understanding of available resources. It can be thought of like a "hint" to the model. Inherited from Resource.descriptionmimeType?: stringThe MIME type of this resource, if known. Inherited from Resource.mimeTypeannotations?: AnnotationsOptional annotations for the client. Inherited from Resource.annotationssize?: numberThe size of the raw resource content, in bytes (i.e., before base64 encoding or any tokenization), if known.

This can be used by Hosts to display file sizes and estimate context window usage. Inherited from Resource.size\_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from Resource.\_metatype: "resource\_link"

### `TextContent`

interface TextContent \{
type: "text";
text: string;
annotations?: Annotations;
\_meta?: \{ \[key: string]: unknown };
}Text provided to or from an LLM. type: "text"text: stringThe text content of the message. annotations?: AnnotationsOptional annotations for the client. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage.

### `TextResourceContents`

interface TextResourceContents \{
uri: string;
mimeType?: string;
\_meta?: \{ \[key: string]: unknown };
text: string;
}uri: stringThe URI of this resource. Inherited from ResourceContents.urimimeType?: stringThe MIME type of this resource, if known. Inherited from ResourceContents.mimeType\_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from ResourceContents.\_metatext: stringThe text of the item. This must only be set if the item can actually be represented as text (not binary data).

## `completion/complete`

### `CompleteRequest`

interface CompleteRequest \{
jsonrpc: "2.0";
id: RequestId;
method: "completion/complete";
params: CompleteRequestParams;
}A request from the client to the server, to ask for completion options. jsonrpc: "2.0"Inherited from JSONRPCRequest.jsonrpcid: RequestIdInherited from JSONRPCRequest.idmethod: "completion/complete"Overrides JSONRPCRequest.methodparams: CompleteRequestParamsOverrides JSONRPCRequest.params

### `CompleteRequestParams`

interface CompleteRequestParams \{
\_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown };
ref: PromptReference | ResourceTemplateReference;
argument: \{ name: string; value: string };
context?: \{ arguments?: \{ \[key: string]: string } };
}Parameters for a completion/complete request. \_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Type Declaration\[key: string]: unknownOptionalprogressToken?: ProgressTokenIf specified, the caller is requesting out-of-band progress notifications for this request (as represented by notifications/progress). The value of this parameter is an opaque token that will be attached to any subsequent notifications. The receiver is not obligated to provide these notifications. Inherited from RequestParams.\_metaref: PromptReference | ResourceTemplateReferenceargument: \{ name: string; value: string }The argument's information Type Declarationname: stringThe name of the argument value: stringThe value of the argument to use for completion matching. context?: \{ arguments?: \{ \[key: string]: string } }Additional, optional context for completions Type DeclarationOptionalarguments?: \{ \[key: string]: string }Previously-resolved variables in a URI template or prompt.

### `CompleteResult`

interface CompleteResult \{
\_meta?: \{ \[key: string]: unknown };
completion: \{ values: string\[]; total?: number; hasMore?: boolean };
\[key: string]: unknown;
}The server's response to a completion/complete request \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from Result.\_metacompletion: \{ values: string\[]; total?: number; hasMore?: boolean }Type Declarationvalues: string\[]An array of completion values. Must not exceed 100 items. Optionaltotal?: numberThe total number of completion options available. This can exceed the number of values actually sent in the response. OptionalhasMore?: booleanIndicates whether there are additional completion options beyond those provided in the current response, even if the exact total is unknown.

### `PromptReference`

interface PromptReference \{
name: string;
title?: string;
type: "ref/prompt";
}Identifies a prompt. name: stringIntended for programmatic or logical use, but used as a display name in past specs or fallback (if title isn't present). Inherited from BaseMetadata.nametitle?: stringIntended for UI and end-user contexts — optimized to be human-readable and easily understood,
even by those unfamiliar with domain-specific terminology.

If not provided, the name should be used for display (except for Tool,
where annotations.title should be given precedence over using name,
if present). Inherited from BaseMetadata.titletype: "ref/prompt"

### `ResourceTemplateReference`

interface ResourceTemplateReference \{
type: "ref/resource";
uri: string;
}A reference to a resource or resource template definition. type: "ref/resource"uri: stringThe URI or URI template of the resource.

## `elicitation/create`

### `ElicitRequest`

interface ElicitRequest \{
jsonrpc: "2.0";
id: RequestId;
method: "elicitation/create";
params: ElicitRequestParams;
}A request from the server to elicit additional information from the user via the client. jsonrpc: "2.0"Inherited from JSONRPCRequest.jsonrpcid: RequestIdInherited from JSONRPCRequest.idmethod: "elicitation/create"Overrides JSONRPCRequest.methodparams: ElicitRequestParamsOverrides JSONRPCRequest.params

### `ElicitRequestParams`

ElicitRequestParams: ElicitRequestFormParams | ElicitRequestURLParamsThe parameters for a request to elicit additional information from the user via the client.

### `ElicitResult`

interface ElicitResult \{
\_meta?: \{ \[key: string]: unknown };
action: "accept" | "decline" | "cancel";
content?: \{ \[key: string]: string | number | boolean | string\[] };
\[key: string]: unknown;
}The client's response to an elicitation request. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from Result.\_metaaction: "accept" | "decline" | "cancel"The user action in response to the elicitation. - "accept": User submitted the form/confirmed the action
- "decline": User explicitly decline the action
- "cancel": User dismissed without making an explicit choice content?: \{ \[key: string]: string | number | boolean | string\[] }The submitted form data, only present when action is "accept" and mode was "form".
Contains values matching the requested schema.
Omitted for out-of-band mode responses.

### `BooleanSchema`

interface BooleanSchema \{
type: "boolean";
title?: string;
description?: string;
default?: boolean;
}type: "boolean"title?: stringdescription?: stringdefault?: boolean

### `ElicitRequestFormParams`

interface ElicitRequestFormParams \{
task?: TaskMetadata;
\_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown };
mode?: "form";
message: string;
requestedSchema: \{
\$schema?: string;
type: "object";
properties: \{ \[key: string]: PrimitiveSchemaDefinition };
required?: string\[];
};
}The parameters for a request to elicit non-sensitive information from the user via a form in the client. task?: TaskMetadataIf specified, the caller is requesting task-augmented execution for this request.
The request will return a CreateTaskResult immediately, and the actual result can be
retrieved later via tasks/result.

Task augmentation is subject to capability negotiation - receivers MUST declare support
for task augmentation of specific request types in their capabilities. Inherited from TaskAugmentedRequestParams.task\_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Type Declaration\[key: string]: unknownOptionalprogressToken?: ProgressTokenIf specified, the caller is requesting out-of-band progress notifications for this request (as represented by notifications/progress). The value of this parameter is an opaque token that will be attached to any subsequent notifications. The receiver is not obligated to provide these notifications. Inherited from TaskAugmentedRequestParams.\_metamode?: "form"The elicitation mode. message: stringThe message to present to the user describing what information is being requested. requestedSchema: \{ \$schema?: string; type: "object"; properties: \{ \[key: string]: PrimitiveSchemaDefinition }; required?: string\[]; }A restricted subset of JSON Schema.
Only top-level properties are allowed, without nesting.

### `ElicitRequestURLParams`

interface ElicitRequestURLParams \{
task?: TaskMetadata;
\_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown };
mode: "url";
message: string;
elicitationId: string;
url: string;
}The parameters for a request to elicit information from the user via a URL in the client. task?: TaskMetadataIf specified, the caller is requesting task-augmented execution for this request.
The request will return a CreateTaskResult immediately, and the actual result can be
retrieved later via tasks/result.

Task augmentation is subject to capability negotiation - receivers MUST declare support
for task augmentation of specific request types in their capabilities. Inherited from TaskAugmentedRequestParams.task\_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Type Declaration\[key: string]: unknownOptionalprogressToken?: ProgressTokenIf specified, the caller is requesting out-of-band progress notifications for this request (as represented by notifications/progress). The value of this parameter is an opaque token that will be attached to any subsequent notifications. The receiver is not obligated to provide these notifications. Inherited from TaskAugmentedRequestParams.\_metamode: "url"The elicitation mode. message: stringThe message to present to the user explaining why the interaction is needed. elicitationId: stringThe ID of the elicitation, which must be unique within the context of the server.
The client MUST treat this ID as an opaque value. url: stringThe URL that the user should navigate to.

### `EnumSchema`

EnumSchema:
| SingleSelectEnumSchema
| MultiSelectEnumSchema
| LegacyTitledEnumSchema

### `LegacyTitledEnumSchema`

interface LegacyTitledEnumSchema \{
type: "string";
title?: string;
description?: string;
enum: string\[];
enumNames?: string\[];
default?: string;
}Use TitledSingleSelectEnumSchema instead.
This interface will be removed in a future version. type: "string"title?: stringdescription?: stringenum: string\[]enumNames?: string\[](Legacy) Display names for enum values.
Non-standard according to JSON schema 2020-12. default?: string

### `MultiSelectEnumSchema`

MultiSelectEnumSchema:
| UntitledMultiSelectEnumSchema
| TitledMultiSelectEnumSchema

### `NumberSchema`

interface NumberSchema \{
type: "number" | "integer";
title?: string;
description?: string;
minimum?: number;
maximum?: number;
default?: number;
}type: "number" | "integer"title?: stringdescription?: stringminimum?: numbermaximum?: numberdefault?: number

### `PrimitiveSchemaDefinition`

PrimitiveSchemaDefinition:
| StringSchema
| NumberSchema
| BooleanSchema
| EnumSchemaRestricted schema definitions that only allow primitive types
without nested objects or arrays.

### `SingleSelectEnumSchema`

SingleSelectEnumSchema:
| UntitledSingleSelectEnumSchema
| TitledSingleSelectEnumSchema

### `StringSchema`

interface StringSchema \{
type: "string";
title?: string;
description?: string;
minLength?: number;
maxLength?: number;
format?: "uri" | "email" | "date" | "date-time";
default?: string;
}type: "string"title?: stringdescription?: stringminLength?: numbermaxLength?: numberformat?: "uri" | "email" | "date" | "date-time"default?: string

### `TitledMultiSelectEnumSchema`

interface TitledMultiSelectEnumSchema \{
type: "array";
title?: string;
description?: string;
minItems?: number;
maxItems?: number;
items: \{ anyOf: \{ const: string; title: string }\[] };
default?: string\[];
}Schema for multiple-selection enumeration with display titles for each option. type: "array"title?: stringOptional title for the enum field. description?: stringOptional description for the enum field. minItems?: numberMinimum number of items to select. maxItems?: numberMaximum number of items to select. items: \{ anyOf: \{ const: string; title: string }\[] }Schema for array items with enum options and display labels. Type DeclarationanyOf: \{ const: string; title: string }\[]Array of enum options with values and display labels. default?: string\[]Optional default value.

### `TitledSingleSelectEnumSchema`

interface TitledSingleSelectEnumSchema \{
type: "string";
title?: string;
description?: string;
oneOf: \{ const: string; title: string }\[];
default?: string;
}Schema for single-selection enumeration with display titles for each option. type: "string"title?: stringOptional title for the enum field. description?: stringOptional description for the enum field. oneOf: \{ const: string; title: string }\[]Array of enum options with values and display labels. Type Declarationconst: stringThe enum value. title: stringDisplay label for this option. default?: stringOptional default value.

### `UntitledMultiSelectEnumSchema`

interface UntitledMultiSelectEnumSchema \{
type: "array";
title?: string;
description?: string;
minItems?: number;
maxItems?: number;
items: \{ type: "string"; enum: string\[] };
default?: string\[];
}Schema for multiple-selection enumeration without display titles for options. type: "array"title?: stringOptional title for the enum field. description?: stringOptional description for the enum field. minItems?: numberMinimum number of items to select. maxItems?: numberMaximum number of items to select. items: \{ type: "string"; enum: string\[] }Schema for the array items. Type Declarationtype: "string"enum: string\[]Array of enum values to choose from. default?: string\[]Optional default value.

### `UntitledSingleSelectEnumSchema`

interface UntitledSingleSelectEnumSchema \{
type: "string";
title?: string;
description?: string;
enum: string\[];
default?: string;
}Schema for single-selection enumeration without display titles for options. type: "string"title?: stringOptional title for the enum field. description?: stringOptional description for the enum field. enum: string\[]Array of enum values to choose from. default?: stringOptional default value.

## `initialize`

### `InitializeRequest`

interface InitializeRequest \{
jsonrpc: "2.0";
id: RequestId;
method: "initialize";
params: InitializeRequestParams;
}This request is sent from the client to the server when it first connects, asking it to begin initialization. jsonrpc: "2.0"Inherited from JSONRPCRequest.jsonrpcid: RequestIdInherited from JSONRPCRequest.idmethod: "initialize"Overrides JSONRPCRequest.methodparams: InitializeRequestParamsOverrides JSONRPCRequest.params

### `InitializeRequestParams`

interface InitializeRequestParams \{
\_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown };
protocolVersion: string;
capabilities: ClientCapabilities;
clientInfo: Implementation;
}Parameters for an initialize request. \_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Type Declaration\[key: string]: unknownOptionalprogressToken?: ProgressTokenIf specified, the caller is requesting out-of-band progress notifications for this request (as represented by notifications/progress). The value of this parameter is an opaque token that will be attached to any subsequent notifications. The receiver is not obligated to provide these notifications. Inherited from RequestParams.\_metaprotocolVersion: stringThe latest version of the Model Context Protocol that the client supports. The client MAY decide to support older versions as well. capabilities: ClientCapabilitiesclientInfo: Implementation

### `InitializeResult`

interface InitializeResult \{
\_meta?: \{ \[key: string]: unknown };
protocolVersion: string;
capabilities: ServerCapabilities;
serverInfo: Implementation;
instructions?: string;
\[key: string]: unknown;
}After receiving an initialize request from the client, the server sends this response. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from Result.\_metaprotocolVersion: stringThe version of the Model Context Protocol that the server wants to use. This may not match the version that the client requested. If the client cannot support this version, it MUST disconnect. capabilities: ServerCapabilitiesserverInfo: Implementationinstructions?: stringInstructions describing how to use the server and its features.

This can be used by clients to improve the LLM's understanding of available tools, resources, etc. It can be thought of like a "hint" to the model. For example, this information MAY be added to the system prompt.

### `ClientCapabilities`

interface ClientCapabilities \{
experimental?: \{ \[key: string]: object };
roots?: \{ listChanged?: boolean };
sampling?: \{ context?: object; tools?: object };
elicitation?: \{ form?: object; url?: object };
tasks?: \{
list?: object;
cancel?: object;
requests?: \{
sampling?: \{ createMessage?: object };
elicitation?: \{ create?: object };
};
};
}Capabilities a client may support. Known capabilities are defined here, in this schema, but this is not a closed set: any client can define its own, additional capabilities. experimental?: \{ \[key: string]: object }Experimental, non-standard capabilities that the client supports. roots?: \{ listChanged?: boolean }Present if the client supports listing roots. Type DeclarationOptionallistChanged?: booleanWhether the client supports notifications for changes to the roots list. sampling?: \{ context?: object; tools?: object }Present if the client supports sampling from an LLM. Type DeclarationOptionalcontext?: objectWhether the client supports context inclusion via includeContext parameter.
If not declared, servers SHOULD only use includeContext: "none" (or omit it). Optionaltools?: objectWhether the client supports tool use via tools and toolChoice parameters. elicitation?: \{ form?: object; url?: object }Present if the client supports elicitation from the server. tasks?: \{ list?: object; cancel?: object; requests?: \{ sampling?: \{ createMessage?: object }; elicitation?: \{ create?: object }; }; }Present if the client supports task-augmented requests. Type DeclarationOptionallist?: objectWhether this client supports tasks/list. Optionalcancel?: objectWhether this client supports tasks/cancel. Optionalrequests?: \{ sampling?: \{ createMessage?: object }; elicitation?: \{ create?: object } }Specifies which request types can be augmented with tasks. Optionalsampling?: \{ createMessage?: object }Task support for sampling-related requests. OptionalcreateMessage?: objectWhether the client supports task-augmented sampling/createMessage requests. Optionalelicitation?: \{ create?: object }Task support for elicitation-related requests. Optionalcreate?: objectWhether the client supports task-augmented elicitation/create requests.

### `Implementation`

interface Implementation \{
icons?: Icon\[];
name: string;
title?: string;
version: string;
description?: string;
websiteUrl?: string;
}Describes the MCP implementation. icons?: Icon\[]Optional set of sized icons that the client can display in a user interface.

Clients that support rendering icons MUST support at least the following MIME types: - image/png - PNG images (safe, universal compatibility)
- image/jpeg (and image/jpg) - JPEG images (safe, universal compatibility) Clients that support rendering icons SHOULD also support: - image/svg+xml - SVG images (scalable but requires security precautions)
- image/webp - WebP images (modern, efficient format) Inherited from Icons.iconsname: stringIntended for programmatic or logical use, but used as a display name in past specs or fallback (if title isn't present). Inherited from BaseMetadata.nametitle?: stringIntended for UI and end-user contexts — optimized to be human-readable and easily understood,
even by those unfamiliar with domain-specific terminology.

If not provided, the name should be used for display (except for Tool,
where annotations.title should be given precedence over using name,
if present). Inherited from BaseMetadata.titleversion: stringdescription?: stringAn optional human-readable description of what this implementation does.

This can be used by clients or servers to provide context about their purpose
and capabilities. For example, a server might describe the types of resources
or tools it provides, while a client might describe its intended use case. websiteUrl?: stringAn optional URL of the website for this implementation.

### `ServerCapabilities`

interface ServerCapabilities \{
experimental?: \{ \[key: string]: object };
logging?: object;
completions?: object;
prompts?: \{ listChanged?: boolean };
resources?: \{ subscribe?: boolean; listChanged?: boolean };
tools?: \{ listChanged?: boolean };
tasks?: \{
list?: object;
cancel?: object;
requests?: \{ tools?: \{ call?: object } };
};
}Capabilities that a server may support. Known capabilities are defined here, in this schema, but this is not a closed set: any server can define its own, additional capabilities. experimental?: \{ \[key: string]: object }Experimental, non-standard capabilities that the server supports. logging?: objectPresent if the server supports sending log messages to the client. completions?: objectPresent if the server supports argument autocompletion suggestions. prompts?: \{ listChanged?: boolean }Present if the server offers any prompt templates. Type DeclarationOptionallistChanged?: booleanWhether this server supports notifications for changes to the prompt list. resources?: \{ subscribe?: boolean; listChanged?: boolean }Present if the server offers any resources to read. Type DeclarationOptionalsubscribe?: booleanWhether this server supports subscribing to resource updates. OptionallistChanged?: booleanWhether this server supports notifications for changes to the resource list. tools?: \{ listChanged?: boolean }Present if the server offers any tools to call. Type DeclarationOptionallistChanged?: booleanWhether this server supports notifications for changes to the tool list. tasks?: \{ list?: object; cancel?: object; requests?: \{ tools?: \{ call?: object } }; }Present if the server supports task-augmented requests. Type DeclarationOptionallist?: objectWhether this server supports tasks/list. Optionalcancel?: objectWhether this server supports tasks/cancel. Optionalrequests?: \{ tools?: \{ call?: object } }Specifies which request types can be augmented with tasks. Optionaltools?: \{ call?: object }Task support for tool-related requests. Optionalcall?: objectWhether the server supports task-augmented tools/call requests.

## `logging/setLevel`

### `SetLevelRequest`

interface SetLevelRequest \{
jsonrpc: "2.0";
id: RequestId;
method: "logging/setLevel";
params: SetLevelRequestParams;
}A request from the client to the server, to enable or adjust logging. jsonrpc: "2.0"Inherited from JSONRPCRequest.jsonrpcid: RequestIdInherited from JSONRPCRequest.idmethod: "logging/setLevel"Overrides JSONRPCRequest.methodparams: SetLevelRequestParamsOverrides JSONRPCRequest.params

### `SetLevelRequestParams`

interface SetLevelRequestParams \{
\_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown };
level: LoggingLevel;
}Parameters for a logging/setLevel request. \_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Type Declaration\[key: string]: unknownOptionalprogressToken?: ProgressTokenIf specified, the caller is requesting out-of-band progress notifications for this request (as represented by notifications/progress). The value of this parameter is an opaque token that will be attached to any subsequent notifications. The receiver is not obligated to provide these notifications. Inherited from RequestParams.\_metalevel: LoggingLevelThe level of logging that the client wants to receive from the server. The server should send all logs at this level and higher (i.e., more severe) to the client as notifications/message.

## `notifications/cancelled`

### `CancelledNotification`

interface CancelledNotification \{
jsonrpc: "2.0";
method: "notifications/cancelled";
params: CancelledNotificationParams;
}This notification can be sent by either side to indicate that it is cancelling a previously-issued request.

The request SHOULD still be in-flight, but due to communication latency, it is always possible that this notification MAY arrive after the request has already finished.

This notification indicates that the result will be unused, so any associated processing SHOULD cease.

A client MUST NOT attempt to cancel its initialize request.

For task cancellation, use the tasks/cancel request instead of this notification. jsonrpc: "2.0"Inherited from JSONRPCNotification.jsonrpcmethod: "notifications/cancelled"Overrides JSONRPCNotification.methodparams: CancelledNotificationParamsOverrides JSONRPCNotification.params

### `CancelledNotificationParams`

interface CancelledNotificationParams \{
\_meta?: \{ \[key: string]: unknown };
requestId?: RequestId;
reason?: string;
}Parameters for a notifications/cancelled notification. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from NotificationParams.\_metarequestId?: RequestIdThe ID of the request to cancel.

This MUST correspond to the ID of a request previously issued in the same direction.
This MUST be provided for cancelling non-task requests.
This MUST NOT be used for cancelling tasks (use the tasks/cancel request instead). reason?: stringAn optional string describing the reason for the cancellation. This MAY be logged or presented to the user.

## `notifications/initialized`

### `InitializedNotification`

interface InitializedNotification \{
jsonrpc: "2.0";
method: "notifications/initialized";
params?: NotificationParams;
}This notification is sent from the client to the server after initialization has finished. jsonrpc: "2.0"Inherited from JSONRPCNotification.jsonrpcmethod: "notifications/initialized"Overrides JSONRPCNotification.methodparams?: NotificationParamsOverrides JSONRPCNotification.params

## `notifications/tasks/status`

### `TaskStatusNotification`

interface TaskStatusNotification \{
jsonrpc: "2.0";
method: "notifications/tasks/status";
params: TaskStatusNotificationParams;
}An optional notification from the receiver to the requestor, informing them that a task's status has changed. Receivers are not required to send these notifications. jsonrpc: "2.0"Inherited from JSONRPCNotification.jsonrpcmethod: "notifications/tasks/status"Overrides JSONRPCNotification.methodparams: TaskStatusNotificationParamsOverrides JSONRPCNotification.params

### `TaskStatusNotificationParams`

TaskStatusNotificationParams: NotificationParams & TaskParameters for a notifications/tasks/status notification.

## `notifications/message`

### `LoggingMessageNotification`

interface LoggingMessageNotification \{
jsonrpc: "2.0";
method: "notifications/message";
params: LoggingMessageNotificationParams;
}JSONRPCNotification of a log message passed from server to client. If no logging/setLevel request has been sent from the client, the server MAY decide which messages to send automatically. jsonrpc: "2.0"Inherited from JSONRPCNotification.jsonrpcmethod: "notifications/message"Overrides JSONRPCNotification.methodparams: LoggingMessageNotificationParamsOverrides JSONRPCNotification.params

### `LoggingMessageNotificationParams`

interface LoggingMessageNotificationParams \{
\_meta?: \{ \[key: string]: unknown };
level: LoggingLevel;
logger?: string;
data: unknown;
}Parameters for a notifications/message notification. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from NotificationParams.\_metalevel: LoggingLevelThe severity of this log message. logger?: stringAn optional name of the logger issuing this message. data: unknownThe data to be logged, such as a string message or an object. Any JSON serializable type is allowed here.

## `notifications/progress`

### `ProgressNotification`

interface ProgressNotification \{
jsonrpc: "2.0";
method: "notifications/progress";
params: ProgressNotificationParams;
}An out-of-band notification used to inform the receiver of a progress update for a long-running request. jsonrpc: "2.0"Inherited from JSONRPCNotification.jsonrpcmethod: "notifications/progress"Overrides JSONRPCNotification.methodparams: ProgressNotificationParamsOverrides JSONRPCNotification.params

### `ProgressNotificationParams`

interface ProgressNotificationParams \{
\_meta?: \{ \[key: string]: unknown };
progressToken: ProgressToken;
progress: number;
total?: number;
message?: string;
}Parameters for a notifications/progress notification. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from NotificationParams.\_metaprogressToken: ProgressTokenThe progress token which was given in the initial request, used to associate this notification with the request that is proceeding. progress: numberThe progress thus far. This should increase every time progress is made, even if the total is unknown. total?: numberTotal number of items to process (or total progress required), if known. message?: stringAn optional message describing the current progress.

## `notifications/prompts/list_changed`

### `PromptListChangedNotification`

interface PromptListChangedNotification \{
jsonrpc: "2.0";
method: "notifications/prompts/list\_changed";
params?: NotificationParams;
}An optional notification from the server to the client, informing it that the list of prompts it offers has changed. This may be issued by servers without any previous subscription from the client. jsonrpc: "2.0"Inherited from JSONRPCNotification.jsonrpcmethod: "notifications/prompts/list\_changed"Overrides JSONRPCNotification.methodparams?: NotificationParamsOverrides JSONRPCNotification.params

## `notifications/resources/list_changed`

### `ResourceListChangedNotification`

interface ResourceListChangedNotification \{
jsonrpc: "2.0";
method: "notifications/resources/list\_changed";
params?: NotificationParams;
}An optional notification from the server to the client, informing it that the list of resources it can read from has changed. This may be issued by servers without any previous subscription from the client. jsonrpc: "2.0"Inherited from JSONRPCNotification.jsonrpcmethod: "notifications/resources/list\_changed"Overrides JSONRPCNotification.methodparams?: NotificationParamsOverrides JSONRPCNotification.params

## `notifications/resources/updated`

### `ResourceUpdatedNotification`

interface ResourceUpdatedNotification \{
jsonrpc: "2.0";
method: "notifications/resources/updated";
params: ResourceUpdatedNotificationParams;
}A notification from the server to the client, informing it that a resource has changed and may need to be read again. This should only be sent if the client previously sent a resources/subscribe request. jsonrpc: "2.0"Inherited from JSONRPCNotification.jsonrpcmethod: "notifications/resources/updated"Overrides JSONRPCNotification.methodparams: ResourceUpdatedNotificationParamsOverrides JSONRPCNotification.params

### `ResourceUpdatedNotificationParams`

interface ResourceUpdatedNotificationParams \{
\_meta?: \{ \[key: string]: unknown };
uri: string;
}Parameters for a notifications/resources/updated notification. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from NotificationParams.\_metauri: stringThe URI of the resource that has been updated. This might be a sub-resource of the one that the client actually subscribed to.

## `notifications/roots/list_changed`

### `RootsListChangedNotification`

interface RootsListChangedNotification \{
jsonrpc: "2.0";
method: "notifications/roots/list\_changed";
params?: NotificationParams;
}A notification from the client to the server, informing it that the list of roots has changed.
This notification should be sent whenever the client adds, removes, or modifies any root.
The server should then request an updated list of roots using the ListRootsRequest. jsonrpc: "2.0"Inherited from JSONRPCNotification.jsonrpcmethod: "notifications/roots/list\_changed"Overrides JSONRPCNotification.methodparams?: NotificationParamsOverrides JSONRPCNotification.params

## `notifications/tools/list_changed`

### `ToolListChangedNotification`

interface ToolListChangedNotification \{
jsonrpc: "2.0";
method: "notifications/tools/list\_changed";
params?: NotificationParams;
}An optional notification from the server to the client, informing it that the list of tools it offers has changed. This may be issued by servers without any previous subscription from the client. jsonrpc: "2.0"Inherited from JSONRPCNotification.jsonrpcmethod: "notifications/tools/list\_changed"Overrides JSONRPCNotification.methodparams?: NotificationParamsOverrides JSONRPCNotification.params

## `notifications/elicitation/complete`

### `ElicitationCompleteNotification`

interface ElicitationCompleteNotification \{
jsonrpc: "2.0";
method: "notifications/elicitation/complete";
params: \{ elicitationId: string };
}An optional notification from the server to the client, informing it of a completion of a out-of-band elicitation request. jsonrpc: "2.0"Inherited from JSONRPCNotification.jsonrpcmethod: "notifications/elicitation/complete"Overrides JSONRPCNotification.methodparams: \{ elicitationId: string }Type DeclarationelicitationId: stringThe ID of the elicitation that completed. Overrides JSONRPCNotification.params

## `ping`

### `PingRequest`

interface PingRequest \{
jsonrpc: "2.0";
id: RequestId;
method: "ping";
params?: RequestParams;
}A ping, issued by either the server or the client, to check that the other party is still alive. The receiver must promptly respond, or else may be disconnected. jsonrpc: "2.0"Inherited from JSONRPCRequest.jsonrpcid: RequestIdInherited from JSONRPCRequest.idmethod: "ping"Overrides JSONRPCRequest.methodparams?: RequestParamsOverrides JSONRPCRequest.params

## `tasks`

### `CreateTaskResult`

interface CreateTaskResult \{
\_meta?: \{ \[key: string]: unknown };
task: Task;
\[key: string]: unknown;
}A response to a task-augmented request. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from Result.\_metatask: Task

### `RelatedTaskMetadata`

interface RelatedTaskMetadata \{
taskId: string;
}Metadata for associating messages with a task.
Include this in the \_meta field under the key io.modelcontextprotocol/related-task. taskId: stringThe task identifier this message is associated with.

### `Task`

interface Task \{
taskId: string;
status: TaskStatus;
statusMessage?: string;
createdAt: string;
lastUpdatedAt: string;
ttl: number | null;
pollInterval?: number;
}Data associated with a task. taskId: stringThe task identifier. status: TaskStatusCurrent task state. statusMessage?: stringOptional human-readable message describing the current task state.
This can provide context for any status, including: - Reasons for "cancelled" status
- Summaries for "completed" status
- Diagnostic information for "failed" status (e.g., error details, what went wrong) createdAt: stringISO 8601 timestamp when the task was created. lastUpdatedAt: stringISO 8601 timestamp when the task was last updated. ttl: number | nullActual retention duration from creation in milliseconds, null for unlimited. pollInterval?: numberSuggested polling interval in milliseconds.

### `TaskMetadata`

interface TaskMetadata \{
ttl?: number;
}Metadata for augmenting a request with task execution.
Include this in the task field of the request parameters. ttl?: numberRequested duration in milliseconds to retain task from creation.

### `TaskStatus`

TaskStatus: "working" | "input\_required" | "completed" | "failed" | "cancelled"The status of a task.

## `tasks/get`

### `GetTaskRequest`

interface GetTaskRequest \{
jsonrpc: "2.0";
id: RequestId;
method: "tasks/get";
params: \{ taskId: string };
}A request to retrieve the state of a task. jsonrpc: "2.0"Inherited from JSONRPCRequest.jsonrpcid: RequestIdInherited from JSONRPCRequest.idmethod: "tasks/get"Overrides JSONRPCRequest.methodparams: \{ taskId: string }Type DeclarationtaskId: stringThe task identifier to query. Overrides JSONRPCRequest.params

### `GetTaskResult`

GetTaskResult: Result & TaskThe response to a tasks/get request.

## `tasks/result`

### `GetTaskPayloadRequest`

interface GetTaskPayloadRequest \{
jsonrpc: "2.0";
id: RequestId;
method: "tasks/result";
params: \{ taskId: string };
}A request to retrieve the result of a completed task. jsonrpc: "2.0"Inherited from JSONRPCRequest.jsonrpcid: RequestIdInherited from JSONRPCRequest.idmethod: "tasks/result"Overrides JSONRPCRequest.methodparams: \{ taskId: string }Type DeclarationtaskId: stringThe task identifier to retrieve results for. Overrides JSONRPCRequest.params

### `GetTaskPayloadResult`

interface GetTaskPayloadResult \{
\_meta?: \{ \[key: string]: unknown };
\[key: string]: unknown;
}The response to a tasks/result request.
The structure matches the result type of the original request.
For example, a tools/call task would return the CallToolResult structure. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from Result.\_meta

## `tasks/list`

### `ListTasksRequest`

interface ListTasksRequest \{
jsonrpc: "2.0";
id: RequestId;
params?: PaginatedRequestParams;
method: "tasks/list";
}A request to retrieve a list of tasks. jsonrpc: "2.0"Inherited from PaginatedRequest.jsonrpcid: RequestIdInherited from PaginatedRequest.idparams?: PaginatedRequestParamsInherited from PaginatedRequest.paramsmethod: "tasks/list"Overrides PaginatedRequest.method

### `ListTasksResult`

interface ListTasksResult \{
\_meta?: \{ \[key: string]: unknown };
nextCursor?: string;
tasks: Task\[];
\[key: string]: unknown;
}The response to a tasks/list request. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from PaginatedResult.\_metanextCursor?: stringAn opaque token representing the pagination position after the last returned result.
If present, there may be more results available. Inherited from PaginatedResult.nextCursortasks: Task\[]

## `tasks/cancel`

### `CancelTaskRequest`

interface CancelTaskRequest \{
jsonrpc: "2.0";
id: RequestId;
method: "tasks/cancel";
params: \{ taskId: string };
}A request to cancel a task. jsonrpc: "2.0"Inherited from JSONRPCRequest.jsonrpcid: RequestIdInherited from JSONRPCRequest.idmethod: "tasks/cancel"Overrides JSONRPCRequest.methodparams: \{ taskId: string }Type DeclarationtaskId: stringThe task identifier to cancel. Overrides JSONRPCRequest.params

### `CancelTaskResult`

CancelTaskResult: Result & TaskThe response to a tasks/cancel request.

## `prompts/get`

### `GetPromptRequest`

interface GetPromptRequest \{
jsonrpc: "2.0";
id: RequestId;
method: "prompts/get";
params: GetPromptRequestParams;
}Used by the client to get a prompt provided by the server. jsonrpc: "2.0"Inherited from JSONRPCRequest.jsonrpcid: RequestIdInherited from JSONRPCRequest.idmethod: "prompts/get"Overrides JSONRPCRequest.methodparams: GetPromptRequestParamsOverrides JSONRPCRequest.params

### `GetPromptRequestParams`

interface GetPromptRequestParams \{
\_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown };
name: string;
arguments?: \{ \[key: string]: string };
}Parameters for a prompts/get request. \_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Type Declaration\[key: string]: unknownOptionalprogressToken?: ProgressTokenIf specified, the caller is requesting out-of-band progress notifications for this request (as represented by notifications/progress). The value of this parameter is an opaque token that will be attached to any subsequent notifications. The receiver is not obligated to provide these notifications. Inherited from RequestParams.\_metaname: stringThe name of the prompt or prompt template. arguments?: \{ \[key: string]: string }Arguments to use for templating the prompt.

### `GetPromptResult`

interface GetPromptResult \{
\_meta?: \{ \[key: string]: unknown };
description?: string;
messages: PromptMessage\[];
\[key: string]: unknown;
}The server's response to a prompts/get request from the client. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from Result.\_metadescription?: stringAn optional description for the prompt. messages: PromptMessage\[]

### `PromptMessage`

interface PromptMessage \{
role: Role;
content: ContentBlock;
}Describes a message returned as part of a prompt.

This is similar to SamplingMessage, but also supports the embedding of
resources from the MCP server. role: Rolecontent: ContentBlock

## `prompts/list`

### `ListPromptsRequest`

interface ListPromptsRequest \{
jsonrpc: "2.0";
id: RequestId;
params?: PaginatedRequestParams;
method: "prompts/list";
}Sent from the client to request a list of prompts and prompt templates the server has. jsonrpc: "2.0"Inherited from PaginatedRequest.jsonrpcid: RequestIdInherited from PaginatedRequest.idparams?: PaginatedRequestParamsInherited from PaginatedRequest.paramsmethod: "prompts/list"Overrides PaginatedRequest.method

### `ListPromptsResult`

interface ListPromptsResult \{
\_meta?: \{ \[key: string]: unknown };
nextCursor?: string;
prompts: Prompt\[];
\[key: string]: unknown;
}The server's response to a prompts/list request from the client. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from PaginatedResult.\_metanextCursor?: stringAn opaque token representing the pagination position after the last returned result.
If present, there may be more results available. Inherited from PaginatedResult.nextCursorprompts: Prompt\[]

### `Prompt`

interface Prompt \{
icons?: Icon\[];
name: string;
title?: string;
description?: string;
arguments?: PromptArgument\[];
\_meta?: \{ \[key: string]: unknown };
}A prompt or prompt template that the server offers. icons?: Icon\[]Optional set of sized icons that the client can display in a user interface.

Clients that support rendering icons MUST support at least the following MIME types: - image/png - PNG images (safe, universal compatibility)
- image/jpeg (and image/jpg) - JPEG images (safe, universal compatibility) Clients that support rendering icons SHOULD also support: - image/svg+xml - SVG images (scalable but requires security precautions)
- image/webp - WebP images (modern, efficient format) Inherited from Icons.iconsname: stringIntended for programmatic or logical use, but used as a display name in past specs or fallback (if title isn't present). Inherited from BaseMetadata.nametitle?: stringIntended for UI and end-user contexts — optimized to be human-readable and easily understood,
even by those unfamiliar with domain-specific terminology.

If not provided, the name should be used for display (except for Tool,
where annotations.title should be given precedence over using name,
if present). Inherited from BaseMetadata.titledescription?: stringAn optional description of what this prompt provides arguments?: PromptArgument\[]A list of arguments to use for templating the prompt. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage.

### `PromptArgument`

interface PromptArgument \{
name: string;
title?: string;
description?: string;
required?: boolean;
}Describes an argument that a prompt can accept. name: stringIntended for programmatic or logical use, but used as a display name in past specs or fallback (if title isn't present). Inherited from BaseMetadata.nametitle?: stringIntended for UI and end-user contexts — optimized to be human-readable and easily understood,
even by those unfamiliar with domain-specific terminology.

If not provided, the name should be used for display (except for Tool,
where annotations.title should be given precedence over using name,
if present). Inherited from BaseMetadata.titledescription?: stringA human-readable description of the argument. required?: booleanWhether this argument must be provided.

## `resources/list`

### `ListResourcesRequest`

interface ListResourcesRequest \{
jsonrpc: "2.0";
id: RequestId;
params?: PaginatedRequestParams;
method: "resources/list";
}Sent from the client to request a list of resources the server has. jsonrpc: "2.0"Inherited from PaginatedRequest.jsonrpcid: RequestIdInherited from PaginatedRequest.idparams?: PaginatedRequestParamsInherited from PaginatedRequest.paramsmethod: "resources/list"Overrides PaginatedRequest.method

### `ListResourcesResult`

interface ListResourcesResult \{
\_meta?: \{ \[key: string]: unknown };
nextCursor?: string;
resources: Resource\[];
\[key: string]: unknown;
}The server's response to a resources/list request from the client. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from PaginatedResult.\_metanextCursor?: stringAn opaque token representing the pagination position after the last returned result.
If present, there may be more results available. Inherited from PaginatedResult.nextCursorresources: Resource\[]

### `Resource`

interface Resource \{
icons?: Icon\[];
name: string;
title?: string;
uri: string;
description?: string;
mimeType?: string;
annotations?: Annotations;
size?: number;
\_meta?: \{ \[key: string]: unknown };
}A known resource that the server is capable of reading. icons?: Icon\[]Optional set of sized icons that the client can display in a user interface.

Clients that support rendering icons MUST support at least the following MIME types: - image/png - PNG images (safe, universal compatibility)
- image/jpeg (and image/jpg) - JPEG images (safe, universal compatibility) Clients that support rendering icons SHOULD also support: - image/svg+xml - SVG images (scalable but requires security precautions)
- image/webp - WebP images (modern, efficient format) Inherited from Icons.iconsname: stringIntended for programmatic or logical use, but used as a display name in past specs or fallback (if title isn't present). Inherited from BaseMetadata.nametitle?: stringIntended for UI and end-user contexts — optimized to be human-readable and easily understood,
even by those unfamiliar with domain-specific terminology.

If not provided, the name should be used for display (except for Tool,
where annotations.title should be given precedence over using name,
if present). Inherited from BaseMetadata.titleuri: stringThe URI of this resource. description?: stringA description of what this resource represents.

This can be used by clients to improve the LLM's understanding of available resources. It can be thought of like a "hint" to the model. mimeType?: stringThe MIME type of this resource, if known. annotations?: AnnotationsOptional annotations for the client. size?: numberThe size of the raw resource content, in bytes (i.e., before base64 encoding or any tokenization), if known.

This can be used by Hosts to display file sizes and estimate context window usage. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage.

## `resources/read`

### `ReadResourceRequest`

interface ReadResourceRequest \{
jsonrpc: "2.0";
id: RequestId;
method: "resources/read";
params: ReadResourceRequestParams;
}Sent from the client to the server, to read a specific resource URI. jsonrpc: "2.0"Inherited from JSONRPCRequest.jsonrpcid: RequestIdInherited from JSONRPCRequest.idmethod: "resources/read"Overrides JSONRPCRequest.methodparams: ReadResourceRequestParamsOverrides JSONRPCRequest.params

### `ReadResourceRequestParams`

interface ReadResourceRequestParams \{
\_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown };
uri: string;
}Parameters for a resources/read request. \_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Type Declaration\[key: string]: unknownOptionalprogressToken?: ProgressTokenIf specified, the caller is requesting out-of-band progress notifications for this request (as represented by notifications/progress). The value of this parameter is an opaque token that will be attached to any subsequent notifications. The receiver is not obligated to provide these notifications. Inherited from ResourceRequestParams.\_metauri: stringThe URI of the resource. The URI can use any protocol; it is up to the server how to interpret it. Inherited from ResourceRequestParams.uri

### `ReadResourceResult`

interface ReadResourceResult \{
\_meta?: \{ \[key: string]: unknown };
contents: (TextResourceContents | BlobResourceContents)\[];
\[key: string]: unknown;
}The server's response to a resources/read request from the client. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from Result.\_metacontents: (TextResourceContents | BlobResourceContents)\[]

## `resources/subscribe`

### `SubscribeRequest`

interface SubscribeRequest \{
jsonrpc: "2.0";
id: RequestId;
method: "resources/subscribe";
params: SubscribeRequestParams;
}Sent from the client to request resources/updated notifications from the server whenever a particular resource changes. jsonrpc: "2.0"Inherited from JSONRPCRequest.jsonrpcid: RequestIdInherited from JSONRPCRequest.idmethod: "resources/subscribe"Overrides JSONRPCRequest.methodparams: SubscribeRequestParamsOverrides JSONRPCRequest.params

### `SubscribeRequestParams`

interface SubscribeRequestParams \{
\_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown };
uri: string;
}Parameters for a resources/subscribe request. \_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Type Declaration\[key: string]: unknownOptionalprogressToken?: ProgressTokenIf specified, the caller is requesting out-of-band progress notifications for this request (as represented by notifications/progress). The value of this parameter is an opaque token that will be attached to any subsequent notifications. The receiver is not obligated to provide these notifications. Inherited from ResourceRequestParams.\_metauri: stringThe URI of the resource. The URI can use any protocol; it is up to the server how to interpret it. Inherited from ResourceRequestParams.uri

## `resources/templates/list`

### `ListResourceTemplatesRequest`

interface ListResourceTemplatesRequest \{
jsonrpc: "2.0";
id: RequestId;
params?: PaginatedRequestParams;
method: "resources/templates/list";
}Sent from the client to request a list of resource templates the server has. jsonrpc: "2.0"Inherited from PaginatedRequest.jsonrpcid: RequestIdInherited from PaginatedRequest.idparams?: PaginatedRequestParamsInherited from PaginatedRequest.paramsmethod: "resources/templates/list"Overrides PaginatedRequest.method

### `ListResourceTemplatesResult`

interface ListResourceTemplatesResult \{
\_meta?: \{ \[key: string]: unknown };
nextCursor?: string;
resourceTemplates: ResourceTemplate\[];
\[key: string]: unknown;
}The server's response to a resources/templates/list request from the client. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from PaginatedResult.\_metanextCursor?: stringAn opaque token representing the pagination position after the last returned result.
If present, there may be more results available. Inherited from PaginatedResult.nextCursorresourceTemplates: ResourceTemplate\[]

### `ResourceTemplate`

interface ResourceTemplate \{
icons?: Icon\[];
name: string;
title?: string;
uriTemplate: string;
description?: string;
mimeType?: string;
annotations?: Annotations;
\_meta?: \{ \[key: string]: unknown };
}A template description for resources available on the server. icons?: Icon\[]Optional set of sized icons that the client can display in a user interface.

Clients that support rendering icons MUST support at least the following MIME types: - image/png - PNG images (safe, universal compatibility)
- image/jpeg (and image/jpg) - JPEG images (safe, universal compatibility) Clients that support rendering icons SHOULD also support: - image/svg+xml - SVG images (scalable but requires security precautions)
- image/webp - WebP images (modern, efficient format) Inherited from Icons.iconsname: stringIntended for programmatic or logical use, but used as a display name in past specs or fallback (if title isn't present). Inherited from BaseMetadata.nametitle?: stringIntended for UI and end-user contexts — optimized to be human-readable and easily understood,
even by those unfamiliar with domain-specific terminology.

If not provided, the name should be used for display (except for Tool,
where annotations.title should be given precedence over using name,
if present). Inherited from BaseMetadata.titleuriTemplate: stringA URI template (according to RFC 6570) that can be used to construct resource URIs. description?: stringA description of what this template is for.

This can be used by clients to improve the LLM's understanding of available resources. It can be thought of like a "hint" to the model. mimeType?: stringThe MIME type for all resources that match this template. This should only be included if all resources matching this template have the same type. annotations?: AnnotationsOptional annotations for the client. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage.

## `resources/unsubscribe`

### `UnsubscribeRequest`

interface UnsubscribeRequest \{
jsonrpc: "2.0";
id: RequestId;
method: "resources/unsubscribe";
params: UnsubscribeRequestParams;
}Sent from the client to request cancellation of resources/updated notifications from the server. This should follow a previous resources/subscribe request. jsonrpc: "2.0"Inherited from JSONRPCRequest.jsonrpcid: RequestIdInherited from JSONRPCRequest.idmethod: "resources/unsubscribe"Overrides JSONRPCRequest.methodparams: UnsubscribeRequestParamsOverrides JSONRPCRequest.params

### `UnsubscribeRequestParams`

interface UnsubscribeRequestParams \{
\_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown };
uri: string;
}Parameters for a resources/unsubscribe request. \_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Type Declaration\[key: string]: unknownOptionalprogressToken?: ProgressTokenIf specified, the caller is requesting out-of-band progress notifications for this request (as represented by notifications/progress). The value of this parameter is an opaque token that will be attached to any subsequent notifications. The receiver is not obligated to provide these notifications. Inherited from ResourceRequestParams.\_metauri: stringThe URI of the resource. The URI can use any protocol; it is up to the server how to interpret it. Inherited from ResourceRequestParams.uri

## `roots/list`

### `ListRootsRequest`

interface ListRootsRequest \{
jsonrpc: "2.0";
id: RequestId;
method: "roots/list";
params?: RequestParams;
}Sent from the server to request a list of root URIs from the client. Roots allow
servers to ask for specific directories or files to operate on. A common example
for roots is providing a set of repositories or directories a server should operate
on.

This request is typically used when the server needs to understand the file system
structure or access specific locations that the client has permission to read from. jsonrpc: "2.0"Inherited from JSONRPCRequest.jsonrpcid: RequestIdInherited from JSONRPCRequest.idmethod: "roots/list"Overrides JSONRPCRequest.methodparams?: RequestParamsOverrides JSONRPCRequest.params

### `ListRootsResult`

interface ListRootsResult \{
\_meta?: \{ \[key: string]: unknown };
roots: Root\[];
\[key: string]: unknown;
}The client's response to a roots/list request from the server.
This result contains an array of Root objects, each representing a root directory
or file that the server can operate on. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from Result.\_metaroots: Root\[]

### `Root`

interface Root \{
uri: string;
name?: string;
\_meta?: \{ \[key: string]: unknown };
}Represents a root directory or file that the server can operate on. uri: stringThe URI identifying the root. This must start with file:// for now.
This restriction may be relaxed in future versions of the protocol to allow
other URI schemes. name?: stringAn optional name for the root. This can be used to provide a human-readable
identifier for the root, which may be useful for display purposes or for
referencing the root in other parts of the application. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage.

## `sampling/createMessage`

### `CreateMessageRequest`

interface CreateMessageRequest \{
jsonrpc: "2.0";
id: RequestId;
method: "sampling/createMessage";
params: CreateMessageRequestParams;
}A request from the server to sample an LLM via the client. The client has full discretion over which model to select. The client should also inform the user before beginning sampling, to allow them to inspect the request (human in the loop) and decide whether to approve it. jsonrpc: "2.0"Inherited from JSONRPCRequest.jsonrpcid: RequestIdInherited from JSONRPCRequest.idmethod: "sampling/createMessage"Overrides JSONRPCRequest.methodparams: CreateMessageRequestParamsOverrides JSONRPCRequest.params

### `CreateMessageRequestParams`

interface CreateMessageRequestParams \{
task?: TaskMetadata;
\_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown };
messages: SamplingMessage\[];
modelPreferences?: ModelPreferences;
systemPrompt?: string;
includeContext?: "none" | "thisServer" | "allServers";
temperature?: number;
maxTokens: number;
stopSequences?: string\[];
metadata?: object;
tools?: Tool\[];
toolChoice?: ToolChoice;
}Parameters for a sampling/createMessage request. task?: TaskMetadataIf specified, the caller is requesting task-augmented execution for this request.
The request will return a CreateTaskResult immediately, and the actual result can be
retrieved later via tasks/result.

Task augmentation is subject to capability negotiation - receivers MUST declare support
for task augmentation of specific request types in their capabilities. Inherited from TaskAugmentedRequestParams.task\_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Type Declaration\[key: string]: unknownOptionalprogressToken?: ProgressTokenIf specified, the caller is requesting out-of-band progress notifications for this request (as represented by notifications/progress). The value of this parameter is an opaque token that will be attached to any subsequent notifications. The receiver is not obligated to provide these notifications. Inherited from TaskAugmentedRequestParams.\_metamessages: SamplingMessage\[]modelPreferences?: ModelPreferencesThe server's preferences for which model to select. The client MAY ignore these preferences. systemPrompt?: stringAn optional system prompt the server wants to use for sampling. The client MAY modify or omit this prompt. includeContext?: "none" | "thisServer" | "allServers"A request to include context from one or more MCP servers (including the caller), to be attached to the prompt.
The client MAY ignore this request.

Default is "none". Values "thisServer" and "allServers" are soft-deprecated. Servers SHOULD only use these values if the client
declares ClientCapabilities.sampling.context. These values may be removed in future spec releases. temperature?: numbermaxTokens: numberThe requested maximum number of tokens to sample (to prevent runaway completions).

The client MAY choose to sample fewer tokens than the requested maximum. stopSequences?: string\[]metadata?: objectOptional metadata to pass through to the LLM provider. The format of this metadata is provider-specific. tools?: Tool\[]Tools that the model may use during generation.
The client MUST return an error if this field is provided but ClientCapabilities.sampling.tools is not declared. toolChoice?: ToolChoiceControls how the model uses tools.
The client MUST return an error if this field is provided but ClientCapabilities.sampling.tools is not declared.
Default is \{ mode: "auto" }.

### `CreateMessageResult`

interface CreateMessageResult \{
\_meta?: \{ \[key: string]: unknown };
model: string;
stopReason?: string;
role: Role;
content: SamplingMessageContentBlock | SamplingMessageContentBlock\[];
\[key: string]: unknown;
}The client's response to a sampling/createMessage request from the server.
The client should inform the user before returning the sampled message, to allow them
to inspect the response (human in the loop) and decide whether to allow the server to see it. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from Result.\_metamodel: stringThe name of the model that generated the message. stopReason?: stringThe reason why sampling stopped, if known.

Standard values: - "endTurn": Natural end of the assistant's turn
- "stopSequence": A stop sequence was encountered
- "maxTokens": Maximum token limit was reached
- "toolUse": The model wants to use one or more tools This field is an open string to allow for provider-specific stop reasons. role: RoleInherited from SamplingMessage.rolecontent: SamplingMessageContentBlock | SamplingMessageContentBlock\[]Inherited from SamplingMessage.content

### `ModelHint`

interface ModelHint \{
name?: string;
}Hints to use for model selection.

Keys not declared here are currently left unspecified by the spec and are up
to the client to interpret. name?: stringA hint for a model name.

The client SHOULD treat this as a substring of a model name; for example: - claude-3-5-sonnet should match claude-3-5-sonnet-20241022
- sonnet should match claude-3-5-sonnet-20241022, claude-3-sonnet-20240229, etc.
- claude should match any Claude model The client MAY also map the string to a different provider's model name or a different model family, as long as it fills a similar niche; for example: - gemini-1.5-flash could match claude-3-haiku-20240307

### `ModelPreferences`

interface ModelPreferences \{
hints?: ModelHint\[];
costPriority?: number;
speedPriority?: number;
intelligencePriority?: number;
}The server's preferences for model selection, requested of the client during sampling.

Because LLMs can vary along multiple dimensions, choosing the "best" model is
rarely straightforward. Different models excel in different areas—some are
faster but less capable, others are more capable but more expensive, and so
on. This interface allows servers to express their priorities across multiple
dimensions to help clients make an appropriate selection for their use case.

These preferences are always advisory. The client MAY ignore them. It is also
up to the client to decide how to interpret these preferences and how to
balance them against other considerations. hints?: ModelHint\[]Optional hints to use for model selection.

If multiple hints are specified, the client MUST evaluate them in order
(such that the first match is taken).

The client SHOULD prioritize these hints over the numeric priorities, but
MAY still use the priorities to select from ambiguous matches. costPriority?: numberHow much to prioritize cost when selecting a model. A value of 0 means cost
is not important, while a value of 1 means cost is the most important
factor. speedPriority?: numberHow much to prioritize sampling speed (latency) when selecting a model. A
value of 0 means speed is not important, while a value of 1 means speed is
the most important factor. intelligencePriority?: numberHow much to prioritize intelligence and capabilities when selecting a
model. A value of 0 means intelligence is not important, while a value of 1
means intelligence is the most important factor.

### `SamplingMessage`

interface SamplingMessage \{
role: Role;
content: SamplingMessageContentBlock | SamplingMessageContentBlock\[];
\_meta?: \{ \[key: string]: unknown };
}Describes a message issued to or received from an LLM API. role: Rolecontent: SamplingMessageContentBlock | SamplingMessageContentBlock\[]\_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage.

### `SamplingMessageContentBlock`

SamplingMessageContentBlock:
| TextContent
| ImageContent
| AudioContent
| ToolUseContent
| ToolResultContent

### `ToolChoice`

interface ToolChoice \{
mode?: "none" | "required" | "auto";
}Controls tool selection behavior for sampling requests. mode?: "none" | "required" | "auto"Controls the tool use ability of the model: - "auto": Model decides whether to use tools (default)
- "required": Model MUST use at least one tool before completing
- "none": Model MUST NOT use any tools

### `ToolResultContent`

interface ToolResultContent \{
type: "tool\_result";
toolUseId: string;
content: ContentBlock\[];
structuredContent?: \{ \[key: string]: unknown };
isError?: boolean;
\_meta?: \{ \[key: string]: unknown };
}The result of a tool use, provided by the user back to the assistant. type: "tool\_result"toolUseId: stringThe ID of the tool use this result corresponds to.

This MUST match the ID from a previous ToolUseContent. content: ContentBlock\[]The unstructured result content of the tool use.

This has the same format as CallToolResult.content and can include text, images,
audio, resource links, and embedded resources. structuredContent?: \{ \[key: string]: unknown }An optional structured result object.

If the tool defined an outputSchema, this SHOULD conform to that schema. isError?: booleanWhether the tool use resulted in an error.

If true, the content typically describes the error that occurred.
Default: false \_meta?: \{ \[key: string]: unknown }Optional metadata about the tool result. Clients SHOULD preserve this field when
including tool results in subsequent sampling requests to enable caching optimizations.

See General fields: \_meta for notes on \_meta usage.

### `ToolUseContent`

interface ToolUseContent \{
type: "tool\_use";
id: string;
name: string;
input: \{ \[key: string]: unknown };
\_meta?: \{ \[key: string]: unknown };
}A request from the assistant to call a tool. type: "tool\_use"id: stringA unique identifier for this tool use.

This ID is used to match tool results to their corresponding tool uses. name: stringThe name of the tool to call. input: \{ \[key: string]: unknown }The arguments to pass to the tool, conforming to the tool's input schema. \_meta?: \{ \[key: string]: unknown }Optional metadata about the tool use. Clients SHOULD preserve this field when
including tool uses in subsequent sampling requests to enable caching optimizations.

See General fields: \_meta for notes on \_meta usage.

## `tools/call`

### `CallToolRequest`

interface CallToolRequest \{
jsonrpc: "2.0";
id: RequestId;
method: "tools/call";
params: CallToolRequestParams;
}Used by the client to invoke a tool provided by the server. jsonrpc: "2.0"Inherited from JSONRPCRequest.jsonrpcid: RequestIdInherited from JSONRPCRequest.idmethod: "tools/call"Overrides JSONRPCRequest.methodparams: CallToolRequestParamsOverrides JSONRPCRequest.params

### `CallToolRequestParams`

interface CallToolRequestParams \{
task?: TaskMetadata;
\_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown };
name: string;
arguments?: \{ \[key: string]: unknown };
}Parameters for a tools/call request. task?: TaskMetadataIf specified, the caller is requesting task-augmented execution for this request.
The request will return a CreateTaskResult immediately, and the actual result can be
retrieved later via tasks/result.

Task augmentation is subject to capability negotiation - receivers MUST declare support
for task augmentation of specific request types in their capabilities. Inherited from TaskAugmentedRequestParams.task\_meta?: \{ progressToken?: ProgressToken; \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Type Declaration\[key: string]: unknownOptionalprogressToken?: ProgressTokenIf specified, the caller is requesting out-of-band progress notifications for this request (as represented by notifications/progress). The value of this parameter is an opaque token that will be attached to any subsequent notifications. The receiver is not obligated to provide these notifications. Inherited from TaskAugmentedRequestParams.\_metaname: stringThe name of the tool. arguments?: \{ \[key: string]: unknown }Arguments to use for the tool call.

### `CallToolResult`

interface CallToolResult \{
\_meta?: \{ \[key: string]: unknown };
content: ContentBlock\[];
structuredContent?: \{ \[key: string]: unknown };
isError?: boolean;
\[key: string]: unknown;
}The server's response to a tool call. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from Result.\_metacontent: ContentBlock\[]A list of content objects that represent the unstructured result of the tool call. structuredContent?: \{ \[key: string]: unknown }An optional JSON object that represents the structured result of the tool call. isError?: booleanWhether the tool call ended in an error.

If not set, this is assumed to be false (the call was successful).

Any errors that originate from the tool SHOULD be reported inside the result
object, with isError set to true, not as an MCP protocol-level error
response. Otherwise, the LLM would not be able to see that an error occurred
and self-correct.

However, any errors in finding the tool, an error indicating that the
server does not support tool calls, or any other exceptional conditions,
should be reported as an MCP error response.

## `tools/list`

### `ListToolsRequest`

interface ListToolsRequest \{
jsonrpc: "2.0";
id: RequestId;
params?: PaginatedRequestParams;
method: "tools/list";
}Sent from the client to request a list of tools the server has. jsonrpc: "2.0"Inherited from PaginatedRequest.jsonrpcid: RequestIdInherited from PaginatedRequest.idparams?: PaginatedRequestParamsInherited from PaginatedRequest.paramsmethod: "tools/list"Overrides PaginatedRequest.method

### `ListToolsResult`

interface ListToolsResult \{
\_meta?: \{ \[key: string]: unknown };
nextCursor?: string;
tools: Tool\[];
\[key: string]: unknown;
}The server's response to a tools/list request from the client. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage. Inherited from PaginatedResult.\_metanextCursor?: stringAn opaque token representing the pagination position after the last returned result.
If present, there may be more results available. Inherited from PaginatedResult.nextCursortools: Tool\[]

### `Tool`

interface Tool \{
icons?: Icon\[];
name: string;
title?: string;
description?: string;
inputSchema: \{
\$schema?: string;
type: "object";
properties?: \{ \[key: string]: object };
required?: string\[];
};
execution?: ToolExecution;
outputSchema?: \{
\$schema?: string;
type: "object";
properties?: \{ \[key: string]: object };
required?: string\[];
};
annotations?: ToolAnnotations;
\_meta?: \{ \[key: string]: unknown };
}Definition for a tool the client can call. icons?: Icon\[]Optional set of sized icons that the client can display in a user interface.

Clients that support rendering icons MUST support at least the following MIME types: - image/png - PNG images (safe, universal compatibility)
- image/jpeg (and image/jpg) - JPEG images (safe, universal compatibility) Clients that support rendering icons SHOULD also support: - image/svg+xml - SVG images (scalable but requires security precautions)
- image/webp - WebP images (modern, efficient format) Inherited from Icons.iconsname: stringIntended for programmatic or logical use, but used as a display name in past specs or fallback (if title isn't present). Inherited from BaseMetadata.nametitle?: stringIntended for UI and end-user contexts — optimized to be human-readable and easily understood,
even by those unfamiliar with domain-specific terminology.

If not provided, the name should be used for display (except for Tool,
where annotations.title should be given precedence over using name,
if present). Inherited from BaseMetadata.titledescription?: stringA human-readable description of the tool.

This can be used by clients to improve the LLM's understanding of available tools. It can be thought of like a "hint" to the model. inputSchema: \{ \$schema?: string; type: "object"; properties?: \{ \[key: string]: object }; required?: string\[]; }A JSON Schema object defining the expected parameters for the tool. execution?: ToolExecutionExecution-related properties for this tool. outputSchema?: \{ \$schema?: string; type: "object"; properties?: \{ \[key: string]: object }; required?: string\[]; }An optional JSON Schema object defining the structure of the tool's output returned in
the structuredContent field of a CallToolResult.

Defaults to JSON Schema 2020-12 when no explicit \$schema is provided.
Currently restricted to type: "object" at the root level. annotations?: ToolAnnotationsOptional additional tool information.

Display name precedence order is: title, annotations.title, then name. \_meta?: \{ \[key: string]: unknown }See General fields: \_meta for notes on \_meta usage.

### `ToolAnnotations`

interface ToolAnnotations \{
title?: string;
readOnlyHint?: boolean;
destructiveHint?: boolean;
idempotentHint?: boolean;
openWorldHint?: boolean;
}Additional properties describing a Tool to clients.

NOTE: all properties in ToolAnnotations are hints.
They are not guaranteed to provide a faithful description of
tool behavior (including descriptive properties like title).

Clients should never make tool use decisions based on ToolAnnotations
received from untrusted servers. title?: stringA human-readable title for the tool. readOnlyHint?: booleanIf true, the tool does not modify its environment.

Default: false destructiveHint?: booleanIf true, the tool may perform destructive updates to its environment.
If false, the tool performs only additive updates.

(This property is meaningful only when readOnlyHint == false)

Default: true idempotentHint?: booleanIf true, calling the tool repeatedly with the same arguments
will have no additional effect on its environment.

(This property is meaningful only when readOnlyHint == false)

Default: false openWorldHint?: booleanIf true, this tool may interact with an "open world" of external
entities. If false, the tool's domain of interaction is closed.
For example, the world of a web search tool is open, whereas that
of a memory tool is not.

Default: true

### `ToolExecution`

interface ToolExecution \{
taskSupport?: "forbidden" | "optional" | "required";
}Execution-related properties for a tool. taskSupport?: "forbidden" | "optional" | "required"Indicates whether this tool supports task-augmented execution.
This allows clients to handle long-running operations through polling
the task system. - "forbidden": Tool does not support task-augmented execution (default when absent)
- "optional": Tool may support task-augmented execution
- "required": Tool requires task-augmented execution Default: "forbidden"
