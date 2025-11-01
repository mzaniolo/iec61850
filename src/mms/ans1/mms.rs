#[allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused,
    clippy::too_many_arguments
)]
pub mod asn1 {
    extern crate alloc;
    use core::borrow::Borrow;
    use rasn::prelude::*;
    use std::sync::LazyLock;
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    pub enum AccessResult {
        #[rasn(tag(context, 0))]
        failure(DataAccessError),
        success(Data),
    }
    impl From<DataAccessError> for AccessResult {
        fn from(value: DataAccessError) -> Self {
            Self::failure(value)
        }
    }
    impl From<Data> for AccessResult {
        fn from(value: Data) -> Self {
            Self::success(value)
        }
    }
    #[doc = " Anonymous SEQUENCE OF member "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, identifier = "CHOICE")]
    pub enum AnonymousAlternateAccess {
        unnamed(AlternateAccessSelection),
    }
    impl From<AlternateAccessSelection> for AnonymousAlternateAccess {
        fn from(value: AlternateAccessSelection) -> Self {
            Self::unnamed(value)
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct AlternateAccess(pub SequenceOf<AnonymousAlternateAccess>);
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    pub enum AlternateAccessSelectionSelectAlternateAccessAccessSelectionComponent {
        basic(Identifier),
    }
    impl From<Identifier> for AlternateAccessSelectionSelectAlternateAccessAccessSelectionComponent {
        fn from(value: Identifier) -> Self {
            Self::basic(value)
        }
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct AlternateAccessSelectionSelectAlternateAccessAccessSelectionIndexRange {
        #[rasn(tag(context, 0), identifier = "lowIndex")]
        pub low_index: Unsigned32,
        #[rasn(tag(context, 1), identifier = "numberOfElements")]
        pub number_of_elements: Unsigned32,
    }
    impl AlternateAccessSelectionSelectAlternateAccessAccessSelectionIndexRange {
        pub fn new(low_index: Unsigned32, number_of_elements: Unsigned32) -> Self {
            Self {
                low_index,
                number_of_elements,
            }
        }
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    pub enum AlternateAccessSelectionSelectAlternateAccessAccessSelection {
        #[rasn(tag(context, 0))]
        component(AlternateAccessSelectionSelectAlternateAccessAccessSelectionComponent),
        #[rasn(tag(context, 1))]
        index(Unsigned32),
        #[rasn(tag(context, 2))]
        indexRange(AlternateAccessSelectionSelectAlternateAccessAccessSelectionIndexRange),
        #[rasn(tag(context, 3))]
        allElements(()),
    }
    impl From<AlternateAccessSelectionSelectAlternateAccessAccessSelectionComponent>
        for AlternateAccessSelectionSelectAlternateAccessAccessSelection
    {
        fn from(
            value: AlternateAccessSelectionSelectAlternateAccessAccessSelectionComponent,
        ) -> Self {
            Self::component(value)
        }
    }
    impl From<Unsigned32> for AlternateAccessSelectionSelectAlternateAccessAccessSelection {
        fn from(value: Unsigned32) -> Self {
            Self::index(value)
        }
    }
    impl From<AlternateAccessSelectionSelectAlternateAccessAccessSelectionIndexRange>
        for AlternateAccessSelectionSelectAlternateAccessAccessSelection
    {
        fn from(
            value: AlternateAccessSelectionSelectAlternateAccessAccessSelectionIndexRange,
        ) -> Self {
            Self::indexRange(value)
        }
    }
    impl From<()> for AlternateAccessSelectionSelectAlternateAccessAccessSelection {
        fn from(value: ()) -> Self {
            Self::allElements(value)
        }
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct AlternateAccessSelectionSelectAlternateAccess {
        #[rasn(identifier = "accessSelection")]
        pub access_selection: AlternateAccessSelectionSelectAlternateAccessAccessSelection,
        #[rasn(identifier = "alternateAccess")]
        pub alternate_access: AlternateAccess,
    }
    impl AlternateAccessSelectionSelectAlternateAccess {
        pub fn new(
            access_selection: AlternateAccessSelectionSelectAlternateAccessAccessSelection,
            alternate_access: AlternateAccess,
        ) -> Self {
            Self {
                access_selection,
                alternate_access,
            }
        }
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    pub enum AlternateAccessSelectionSelectAccessComponent {
        basic(Identifier),
    }
    impl From<Identifier> for AlternateAccessSelectionSelectAccessComponent {
        fn from(value: Identifier) -> Self {
            Self::basic(value)
        }
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct AlternateAccessSelectionSelectAccessIndexRange {
        #[rasn(tag(context, 0), identifier = "lowIndex")]
        pub low_index: Unsigned32,
        #[rasn(tag(context, 1), identifier = "numberOfElements")]
        pub number_of_elements: Unsigned32,
    }
    impl AlternateAccessSelectionSelectAccessIndexRange {
        pub fn new(low_index: Unsigned32, number_of_elements: Unsigned32) -> Self {
            Self {
                low_index,
                number_of_elements,
            }
        }
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    pub enum AlternateAccessSelectionSelectAccess {
        #[rasn(tag(context, 1))]
        component(AlternateAccessSelectionSelectAccessComponent),
        #[rasn(tag(context, 2))]
        index(Unsigned32),
        #[rasn(tag(context, 3))]
        indexRange(AlternateAccessSelectionSelectAccessIndexRange),
        #[rasn(tag(context, 4))]
        allElements(()),
    }
    impl From<AlternateAccessSelectionSelectAccessComponent> for AlternateAccessSelectionSelectAccess {
        fn from(value: AlternateAccessSelectionSelectAccessComponent) -> Self {
            Self::component(value)
        }
    }
    impl From<Unsigned32> for AlternateAccessSelectionSelectAccess {
        fn from(value: Unsigned32) -> Self {
            Self::index(value)
        }
    }
    impl From<AlternateAccessSelectionSelectAccessIndexRange> for AlternateAccessSelectionSelectAccess {
        fn from(value: AlternateAccessSelectionSelectAccessIndexRange) -> Self {
            Self::indexRange(value)
        }
    }
    impl From<()> for AlternateAccessSelectionSelectAccess {
        fn from(value: ()) -> Self {
            Self::allElements(value)
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    pub enum AlternateAccessSelection {
        #[rasn(tag(context, 0))]
        selectAlternateAccess(AlternateAccessSelectionSelectAlternateAccess),
        selectAccess(AlternateAccessSelectionSelectAccess),
    }
    impl From<AlternateAccessSelectionSelectAlternateAccess> for AlternateAccessSelection {
        fn from(value: AlternateAccessSelectionSelectAlternateAccess) -> Self {
            Self::selectAlternateAccess(value)
        }
    }
    impl From<AlternateAccessSelectionSelectAccess> for AlternateAccessSelection {
        fn from(value: AlternateAccessSelectionSelectAccess) -> Self {
            Self::selectAccess(value)
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash, Copy)]
    #[rasn(delegate, identifier = "Conclude-RequestPDU")]
    pub struct ConcludeRequestPDU(pub ());
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "Confirmed-ErrorPDU")]
    pub struct ConfirmedErrorPDU {
        #[rasn(tag(context, 0), identifier = "invokeID")]
        pub invoke_id: Unsigned32,
        #[rasn(tag(context, 1), identifier = "modifierPosition")]
        pub modifier_position: Option<Unsigned32>,
        #[rasn(tag(context, 2), identifier = "serviceError")]
        pub service_error: ServiceError,
    }
    impl ConfirmedErrorPDU {
        pub fn new(
            invoke_id: Unsigned32,
            modifier_position: Option<Unsigned32>,
            service_error: ServiceError,
        ) -> Self {
            Self {
                invoke_id,
                modifier_position,
                service_error,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "Confirmed-RequestPDU")]
    pub struct ConfirmedRequestPDU {
        #[rasn(identifier = "invokeID")]
        pub invoke_id: Unsigned32,
        pub service: ConfirmedServiceRequest,
    }
    impl ConfirmedRequestPDU {
        pub fn new(invoke_id: Unsigned32, service: ConfirmedServiceRequest) -> Self {
            Self { invoke_id, service }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "Confirmed-ResponsePDU")]
    pub struct ConfirmedResponsePDU {
        #[rasn(identifier = "invokeID")]
        pub invoke_id: Unsigned32,
        pub service: ConfirmedServiceResponse,
    }
    impl ConfirmedResponsePDU {
        pub fn new(invoke_id: Unsigned32, service: ConfirmedServiceResponse) -> Self {
            Self { invoke_id, service }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    pub enum ConfirmedServiceRequest {
        #[rasn(tag(context, 1))]
        getNameList(GetNameListRequest),
        #[rasn(tag(context, 4))]
        read(ReadRequest),
        #[rasn(tag(context, 5))]
        write(WriteRequest),
        #[rasn(tag(context, 6))]
        getVariableAccessAttributes(GetVariableAccessAttributesRequest),
        #[rasn(tag(context, 11))]
        defineNamedVariableList(DefineNamedVariableListRequest),
        #[rasn(tag(context, 12))]
        getNamedVariableListAttributes(GetNamedVariableListAttributesRequest),
        #[rasn(tag(context, 13))]
        deleteNamedVariableList(DeleteNamedVariableListRequest),
        #[rasn(tag(context, 72))]
        fileOpen(FileOpenRequest),
        #[rasn(tag(context, 73))]
        fileRead(FileReadRequest),
        #[rasn(tag(context, 74))]
        fileClose(FileCloseRequest),
        #[rasn(tag(context, 76))]
        fileDelete(FileDeleteRequest),
        #[rasn(tag(context, 77))]
        fileDirectory(FileDirectoryRequest),
    }
    impl From<GetNameListRequest> for ConfirmedServiceRequest {
        fn from(value: GetNameListRequest) -> Self {
            Self::getNameList(value)
        }
    }
    impl From<ReadRequest> for ConfirmedServiceRequest {
        fn from(value: ReadRequest) -> Self {
            Self::read(value)
        }
    }
    impl From<WriteRequest> for ConfirmedServiceRequest {
        fn from(value: WriteRequest) -> Self {
            Self::write(value)
        }
    }
    impl From<GetVariableAccessAttributesRequest> for ConfirmedServiceRequest {
        fn from(value: GetVariableAccessAttributesRequest) -> Self {
            Self::getVariableAccessAttributes(value)
        }
    }
    impl From<DefineNamedVariableListRequest> for ConfirmedServiceRequest {
        fn from(value: DefineNamedVariableListRequest) -> Self {
            Self::defineNamedVariableList(value)
        }
    }
    impl From<GetNamedVariableListAttributesRequest> for ConfirmedServiceRequest {
        fn from(value: GetNamedVariableListAttributesRequest) -> Self {
            Self::getNamedVariableListAttributes(value)
        }
    }
    impl From<DeleteNamedVariableListRequest> for ConfirmedServiceRequest {
        fn from(value: DeleteNamedVariableListRequest) -> Self {
            Self::deleteNamedVariableList(value)
        }
    }
    impl From<FileOpenRequest> for ConfirmedServiceRequest {
        fn from(value: FileOpenRequest) -> Self {
            Self::fileOpen(value)
        }
    }
    impl From<FileReadRequest> for ConfirmedServiceRequest {
        fn from(value: FileReadRequest) -> Self {
            Self::fileRead(value)
        }
    }
    impl From<FileCloseRequest> for ConfirmedServiceRequest {
        fn from(value: FileCloseRequest) -> Self {
            Self::fileClose(value)
        }
    }
    impl From<FileDeleteRequest> for ConfirmedServiceRequest {
        fn from(value: FileDeleteRequest) -> Self {
            Self::fileDelete(value)
        }
    }
    impl From<FileDirectoryRequest> for ConfirmedServiceRequest {
        fn from(value: FileDirectoryRequest) -> Self {
            Self::fileDirectory(value)
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    pub enum ConfirmedServiceResponse {
        #[rasn(tag(context, 1))]
        getNameList(GetNameListResponse),
        #[rasn(tag(context, 4))]
        read(ReadResponse),
        #[rasn(tag(context, 5))]
        write(WriteResponse),
        #[rasn(tag(context, 6))]
        getVariableAccessAttributes(GetVariableAccessAttributesResponse),
        #[rasn(tag(context, 11))]
        defineNamedVariableList(DefineNamedVariableListResponse),
        #[rasn(tag(context, 12))]
        getNamedVariableListAttributes(GetNamedVariableListAttributesResponse),
        #[rasn(tag(context, 13))]
        deleteNamedVariableList(DeleteNamedVariableListResponse),
        #[rasn(tag(context, 72))]
        fileOpen(FileOpenResponse),
        #[rasn(tag(context, 73))]
        fileRead(FileReadResponse),
        #[rasn(tag(context, 74))]
        fileClose(FileCloseResponse),
        #[rasn(tag(context, 76))]
        fileDelete(FileDeleteResponse),
        #[rasn(tag(context, 77))]
        fileDirectory(FileDirectoryResponse),
    }
    impl From<GetNameListResponse> for ConfirmedServiceResponse {
        fn from(value: GetNameListResponse) -> Self {
            Self::getNameList(value)
        }
    }
    impl From<ReadResponse> for ConfirmedServiceResponse {
        fn from(value: ReadResponse) -> Self {
            Self::read(value)
        }
    }
    impl From<WriteResponse> for ConfirmedServiceResponse {
        fn from(value: WriteResponse) -> Self {
            Self::write(value)
        }
    }
    impl From<GetVariableAccessAttributesResponse> for ConfirmedServiceResponse {
        fn from(value: GetVariableAccessAttributesResponse) -> Self {
            Self::getVariableAccessAttributes(value)
        }
    }
    impl From<DefineNamedVariableListResponse> for ConfirmedServiceResponse {
        fn from(value: DefineNamedVariableListResponse) -> Self {
            Self::defineNamedVariableList(value)
        }
    }
    impl From<GetNamedVariableListAttributesResponse> for ConfirmedServiceResponse {
        fn from(value: GetNamedVariableListAttributesResponse) -> Self {
            Self::getNamedVariableListAttributes(value)
        }
    }
    impl From<DeleteNamedVariableListResponse> for ConfirmedServiceResponse {
        fn from(value: DeleteNamedVariableListResponse) -> Self {
            Self::deleteNamedVariableList(value)
        }
    }
    impl From<FileOpenResponse> for ConfirmedServiceResponse {
        fn from(value: FileOpenResponse) -> Self {
            Self::fileOpen(value)
        }
    }
    impl From<FileReadResponse> for ConfirmedServiceResponse {
        fn from(value: FileReadResponse) -> Self {
            Self::fileRead(value)
        }
    }
    impl From<FileCloseResponse> for ConfirmedServiceResponse {
        fn from(value: FileCloseResponse) -> Self {
            Self::fileClose(value)
        }
    }
    impl From<FileDeleteResponse> for ConfirmedServiceResponse {
        fn from(value: FileDeleteResponse) -> Self {
            Self::fileDelete(value)
        }
    }
    impl From<FileDirectoryResponse> for ConfirmedServiceResponse {
        fn from(value: FileDirectoryResponse) -> Self {
            Self::fileDirectory(value)
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    pub enum Data {
        #[rasn(tag(context, 1))]
        array(SequenceOf<Data>),
        #[rasn(tag(context, 2))]
        structure(SequenceOf<Data>),
        #[rasn(tag(context, 3))]
        bool(bool),
        #[rasn(tag(context, 4), identifier = "bit-string")]
        bit_string(BitString),
        #[rasn(tag(context, 5))]
        integer(Integer),
        #[rasn(tag(context, 6))]
        unsigned(Integer),
        #[rasn(tag(context, 7), identifier = "floating-point")]
        floating_point(FloatingPoint),
        #[rasn(tag(context, 9), identifier = "octet-string")]
        octet_string(OctetString),
        #[rasn(tag(context, 10), identifier = "visible-string")]
        visible_string(VisibleString),
        #[rasn(tag(context, 12), identifier = "binary-time")]
        binary_time(TimeOfDay),
        #[rasn(tag(context, 16))]
        mMSString(MMSString),
        #[rasn(tag(context, 17), identifier = "utc-time")]
        utc_time(UtcTime),
    }
    impl From<bool> for Data {
        fn from(value: bool) -> Self {
            Self::bool(value)
        }
    }
    impl From<BitString> for Data {
        fn from(value: BitString) -> Self {
            Self::bit_string(value)
        }
    }
    impl From<FloatingPoint> for Data {
        fn from(value: FloatingPoint) -> Self {
            Self::floating_point(value)
        }
    }
    impl From<OctetString> for Data {
        fn from(value: OctetString) -> Self {
            Self::octet_string(value)
        }
    }
    impl From<VisibleString> for Data {
        fn from(value: VisibleString) -> Self {
            Self::visible_string(value)
        }
    }
    impl From<TimeOfDay> for Data {
        fn from(value: TimeOfDay) -> Self {
            Self::binary_time(value)
        }
    }
    impl From<MMSString> for Data {
        fn from(value: MMSString) -> Self {
            Self::mMSString(value)
        }
    }
    impl From<UtcTime> for Data {
        fn from(value: UtcTime) -> Self {
            Self::utc_time(value)
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct DataAccessError(pub Integer);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "DefineNamedVariableList-Request")]
    pub struct DefineNamedVariableListRequest {
        #[rasn(identifier = "variableListName")]
        pub variable_list_name: ObjectName,
        #[rasn(tag(context, 0), identifier = "listOfVariable")]
        pub list_of_variable: VariableDefs,
    }
    impl DefineNamedVariableListRequest {
        pub fn new(variable_list_name: ObjectName, list_of_variable: VariableDefs) -> Self {
            Self {
                variable_list_name,
                list_of_variable,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash, Copy)]
    #[rasn(delegate, identifier = "DefineNamedVariableList-Response")]
    pub struct DefineNamedVariableListResponse(pub ());
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "DeleteNamedVariableList-Request")]
    pub struct DeleteNamedVariableListRequest {
        #[rasn(
            tag(context, 0),
            default = "delete_named_variable_list_request_scope_of_delete_default",
            identifier = "scopeOfDelete"
        )]
        pub scope_of_delete: Integer,
        #[rasn(tag(context, 1), identifier = "listOfVariableListName")]
        pub list_of_variable_list_name: Option<SequenceOf<ObjectName>>,
        #[rasn(tag(context, 2), identifier = "domainName")]
        pub domain_name: Option<Identifier>,
    }
    impl DeleteNamedVariableListRequest {
        pub fn new(
            scope_of_delete: Integer,
            list_of_variable_list_name: Option<SequenceOf<ObjectName>>,
            domain_name: Option<Identifier>,
        ) -> Self {
            Self {
                scope_of_delete,
                list_of_variable_list_name,
                domain_name,
            }
        }
    }
    fn delete_named_variable_list_request_scope_of_delete_default() -> Integer {
        Integer::from(0)
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "DeleteNamedVariableList-Response")]
    pub struct DeleteNamedVariableListResponse {
        #[rasn(tag(context, 0), identifier = "numberMatched")]
        pub number_matched: Unsigned32,
        #[rasn(tag(context, 1), identifier = "numberDeleted")]
        pub number_deleted: Unsigned32,
    }
    impl DeleteNamedVariableListResponse {
        pub fn new(number_matched: Unsigned32, number_deleted: Unsigned32) -> Self {
            Self {
                number_matched,
                number_deleted,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct DirectoryEntry {
        #[rasn(tag(context, 0), identifier = "fileName")]
        pub file_name: FileName,
        #[rasn(tag(context, 1), identifier = "fileAttributes")]
        pub file_attributes: FileAttributes,
    }
    impl DirectoryEntry {
        pub fn new(file_name: FileName, file_attributes: FileAttributes) -> Self {
            Self {
                file_name,
                file_attributes,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct FileAttributes {
        #[rasn(tag(context, 0), identifier = "sizeOfFile")]
        pub size_of_file: Unsigned32,
        #[rasn(tag(context, 1), identifier = "lastModified")]
        pub last_modified: Option<GeneralizedTime>,
    }
    impl FileAttributes {
        pub fn new(size_of_file: Unsigned32, last_modified: Option<GeneralizedTime>) -> Self {
            Self {
                size_of_file,
                last_modified,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, identifier = "FileClose-Request")]
    pub struct FileCloseRequest(pub Integer32);
    #[doc = " FRSM ID"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash, Copy)]
    #[rasn(delegate, identifier = "FileClose-Response")]
    pub struct FileCloseResponse(pub ());
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, identifier = "FileDelete-Request")]
    pub struct FileDeleteRequest(pub FileName);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash, Copy)]
    #[rasn(delegate, identifier = "FileDelete-Response")]
    pub struct FileDeleteResponse(pub ());
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "FileDirectory-Request")]
    pub struct FileDirectoryRequest {
        #[rasn(tag(context, 0), identifier = "fileSpecification")]
        pub file_specification: Option<FileName>,
        #[rasn(tag(context, 1), identifier = "continueAfter")]
        pub continue_after: Option<FileName>,
    }
    impl FileDirectoryRequest {
        pub fn new(file_specification: Option<FileName>, continue_after: Option<FileName>) -> Self {
            Self {
                file_specification,
                continue_after,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "FileDirectory-Response")]
    pub struct FileDirectoryResponse {
        #[rasn(tag(context, 0), identifier = "listOfDirectoryEntry")]
        pub list_of_directory_entry: SequenceOf<DirectoryEntry>,
        #[rasn(
            tag(context, 1),
            default = "file_directory_response_more_follows_default",
            identifier = "moreFollows"
        )]
        pub more_follows: bool,
    }
    impl FileDirectoryResponse {
        pub fn new(
            list_of_directory_entry: SequenceOf<DirectoryEntry>,
            more_follows: bool,
        ) -> Self {
            Self {
                list_of_directory_entry,
                more_follows,
            }
        }
    }
    fn file_directory_response_more_follows_default() -> bool {
        false
    }
    #[doc = " Anonymous SEQUENCE OF member "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, identifier = "GraphicString")]
    pub struct AnonymousFileName(pub GraphicString);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct FileName(pub SequenceOf<AnonymousFileName>);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "FileOpen-Request")]
    pub struct FileOpenRequest {
        #[rasn(tag(context, 0), identifier = "fileName")]
        pub file_name: FileName,
        #[rasn(tag(context, 1), identifier = "initialPosition")]
        pub initial_position: Unsigned32,
    }
    impl FileOpenRequest {
        pub fn new(file_name: FileName, initial_position: Unsigned32) -> Self {
            Self {
                file_name,
                initial_position,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "FileOpen-Response")]
    pub struct FileOpenResponse {
        #[rasn(tag(context, 0), identifier = "frsmID")]
        pub frsm_id: Integer32,
        #[rasn(tag(context, 1), identifier = "fileAttributes")]
        pub file_attributes: FileAttributes,
    }
    impl FileOpenResponse {
        pub fn new(frsm_id: Integer32, file_attributes: FileAttributes) -> Self {
            Self {
                frsm_id,
                file_attributes,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, identifier = "FileRead-Request")]
    pub struct FileReadRequest(pub Integer32);
    #[doc = " FRSM ID"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "FileRead-Response")]
    pub struct FileReadResponse {
        #[rasn(tag(context, 0), identifier = "fileData")]
        pub file_data: OctetString,
        #[rasn(
            tag(context, 1),
            default = "file_read_response_more_follows_default",
            identifier = "moreFollows"
        )]
        pub more_follows: bool,
    }
    impl FileReadResponse {
        pub fn new(file_data: OctetString, more_follows: bool) -> Self {
            Self {
                file_data,
                more_follows,
            }
        }
    }
    fn file_read_response_more_follows_default() -> bool {
        true
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct FloatingPoint(pub OctetString);
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    pub enum GetNameListRequestObjectScope {
        #[rasn(tag(context, 0))]
        vmdSpecific(()),
        #[rasn(tag(context, 1))]
        domainSpecific(Identifier),
        #[rasn(tag(context, 2))]
        aaSpecific(()),
    }
    impl From<Identifier> for GetNameListRequestObjectScope {
        fn from(value: Identifier) -> Self {
            Self::domainSpecific(value)
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "GetNameList-Request")]
    pub struct GetNameListRequest {
        #[rasn(tag(context, 0), identifier = "objectClass")]
        pub object_class: ObjectClass,
        #[rasn(tag(context, 1), identifier = "objectScope")]
        pub object_scope: GetNameListRequestObjectScope,
        #[rasn(tag(context, 2), identifier = "continueAfter")]
        pub continue_after: Option<Identifier>,
    }
    impl GetNameListRequest {
        pub fn new(
            object_class: ObjectClass,
            object_scope: GetNameListRequestObjectScope,
            continue_after: Option<Identifier>,
        ) -> Self {
            Self {
                object_class,
                object_scope,
                continue_after,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "GetNameList-Response")]
    pub struct GetNameListResponse {
        #[rasn(tag(context, 0), identifier = "listOfIdentifier")]
        pub list_of_identifier: SequenceOf<Identifier>,
        #[rasn(
            tag(context, 1),
            default = "get_name_list_response_more_follows_default",
            identifier = "moreFollows"
        )]
        pub more_follows: bool,
    }
    impl GetNameListResponse {
        pub fn new(list_of_identifier: SequenceOf<Identifier>, more_follows: bool) -> Self {
            Self {
                list_of_identifier,
                more_follows,
            }
        }
    }
    fn get_name_list_response_more_follows_default() -> bool {
        true
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, identifier = "GetNamedVariableListAttributes-Request")]
    pub struct GetNamedVariableListAttributesRequest(pub ObjectName);
    #[doc = " VariableListName"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "GetNamedVariableListAttributes-Response")]
    pub struct GetNamedVariableListAttributesResponse {
        #[rasn(tag(context, 0), identifier = "mmsDeletable")]
        pub mms_deletable: bool,
        #[rasn(tag(context, 1), identifier = "listOfVariable")]
        pub list_of_variable: VariableDefs,
    }
    impl GetNamedVariableListAttributesResponse {
        pub fn new(mms_deletable: bool, list_of_variable: VariableDefs) -> Self {
            Self {
                mms_deletable,
                list_of_variable,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, identifier = "GetVariableAccessAttributes-Request")]
    pub enum GetVariableAccessAttributesRequest {
        #[rasn(tag(context, 0))]
        name(ObjectName),
    }
    impl From<ObjectName> for GetVariableAccessAttributesRequest {
        fn from(value: ObjectName) -> Self {
            Self::name(value)
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "GetVariableAccessAttributes-Response")]
    pub struct GetVariableAccessAttributesResponse {
        #[rasn(tag(context, 0), identifier = "mmsDeletable")]
        pub mms_deletable: bool,
        #[rasn(tag(context, 2), identifier = "typeSpecification")]
        pub type_specification: TypeSpecification,
    }
    impl GetVariableAccessAttributesResponse {
        pub fn new(mms_deletable: bool, type_specification: TypeSpecification) -> Self {
            Self {
                mms_deletable,
                type_specification,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct Identifier(pub VisibleString);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct InformationReport {
        #[rasn(identifier = "variableAccessSpecification")]
        pub variable_access_specification: VariableAccessSpecification,
        #[rasn(tag(context, 0), identifier = "listOfAccessResult")]
        pub list_of_access_result: SequenceOf<AccessResult>,
    }
    impl InformationReport {
        pub fn new(
            variable_access_specification: VariableAccessSpecification,
            list_of_access_result: SequenceOf<AccessResult>,
        ) -> Self {
            Self {
                variable_access_specification,
                list_of_access_result,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, identifier = "Initiate-ErrorPDU")]
    pub struct InitiateErrorPDU(pub ServiceError);
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct InitiateRequestPDUInitRequestDetail {
        #[rasn(tag(context, 0), identifier = "proposedVersionNumber")]
        pub proposed_version_number: Integer16,
        #[rasn(tag(context, 1), identifier = "proposedParameterCBB")]
        pub proposed_parameter_cbb: ParameterSupportOptions,
        #[rasn(tag(context, 2), identifier = "servicesSupportedCalling")]
        pub services_supported_calling: ServiceSupportOptions,
    }
    impl InitiateRequestPDUInitRequestDetail {
        pub fn new(
            proposed_version_number: Integer16,
            proposed_parameter_cbb: ParameterSupportOptions,
            services_supported_calling: ServiceSupportOptions,
        ) -> Self {
            Self {
                proposed_version_number,
                proposed_parameter_cbb,
                services_supported_calling,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "Initiate-RequestPDU")]
    pub struct InitiateRequestPDU {
        #[rasn(tag(context, 0), identifier = "localDetailCalling")]
        pub local_detail_calling: Option<Integer32>,
        #[rasn(tag(context, 1), identifier = "proposedMaxServOutstandingCalling")]
        pub proposed_max_serv_outstanding_calling: Integer16,
        #[rasn(tag(context, 2), identifier = "proposedMaxServOutstandingCalled")]
        pub proposed_max_serv_outstanding_called: Integer16,
        #[rasn(tag(context, 3), identifier = "proposedDataStructureNestingLevel")]
        pub proposed_data_structure_nesting_level: Option<Integer8>,
        #[rasn(tag(context, 4), identifier = "initRequestDetail")]
        pub init_request_detail: InitiateRequestPDUInitRequestDetail,
    }
    impl InitiateRequestPDU {
        pub fn new(
            local_detail_calling: Option<Integer32>,
            proposed_max_serv_outstanding_calling: Integer16,
            proposed_max_serv_outstanding_called: Integer16,
            proposed_data_structure_nesting_level: Option<Integer8>,
            init_request_detail: InitiateRequestPDUInitRequestDetail,
        ) -> Self {
            Self {
                local_detail_calling,
                proposed_max_serv_outstanding_calling,
                proposed_max_serv_outstanding_called,
                proposed_data_structure_nesting_level,
                init_request_detail,
            }
        }
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct InitiateResponsePDUInitResponseDetail {
        #[rasn(tag(context, 0), identifier = "negotiatedVersionNumber")]
        pub negotiated_version_number: Integer16,
        #[rasn(tag(context, 1), identifier = "negotiatedParameterCBB")]
        pub negotiated_parameter_cbb: ParameterSupportOptions,
        #[rasn(tag(context, 2), identifier = "servicesSupportedCalled")]
        pub services_supported_called: ServiceSupportOptions,
    }
    impl InitiateResponsePDUInitResponseDetail {
        pub fn new(
            negotiated_version_number: Integer16,
            negotiated_parameter_cbb: ParameterSupportOptions,
            services_supported_called: ServiceSupportOptions,
        ) -> Self {
            Self {
                negotiated_version_number,
                negotiated_parameter_cbb,
                services_supported_called,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "Initiate-ResponsePDU")]
    pub struct InitiateResponsePDU {
        #[rasn(tag(context, 0), identifier = "localDetailCalled")]
        pub local_detail_called: Option<Integer32>,
        #[rasn(tag(context, 1), identifier = "negotiatedMaxServOutstandingCalling")]
        pub negotiated_max_serv_outstanding_calling: Integer16,
        #[rasn(tag(context, 2), identifier = "negotiatedMaxServOutstandingCalled")]
        pub negotiated_max_serv_outstanding_called: Integer16,
        #[rasn(tag(context, 3), identifier = "negotiatedDataStructureNestingLevel")]
        pub negotiated_data_structure_nesting_level: Option<Integer8>,
        #[rasn(tag(context, 4), identifier = "initResponseDetail")]
        pub init_response_detail: InitiateResponsePDUInitResponseDetail,
    }
    impl InitiateResponsePDU {
        pub fn new(
            local_detail_called: Option<Integer32>,
            negotiated_max_serv_outstanding_calling: Integer16,
            negotiated_max_serv_outstanding_called: Integer16,
            negotiated_data_structure_nesting_level: Option<Integer8>,
            init_response_detail: InitiateResponsePDUInitResponseDetail,
        ) -> Self {
            Self {
                local_detail_called,
                negotiated_max_serv_outstanding_calling,
                negotiated_max_serv_outstanding_called,
                negotiated_data_structure_nesting_level,
                init_response_detail,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("-32768..=32767"))]
    pub struct Integer16(pub i16);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("-2147483648..=2147483647"))]
    pub struct Integer32(pub i32);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("-128..=127"))]
    pub struct Integer8(pub i8);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct MMSString(pub VisibleString);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    pub enum MMSpdu {
        #[rasn(tag(context, 0), identifier = "confirmed-RequestPDU")]
        confirmed_RequestPDU(ConfirmedRequestPDU),
        #[rasn(tag(context, 1), identifier = "confirmed-ResponsePDU")]
        confirmed_ResponsePDU(ConfirmedResponsePDU),
        #[rasn(tag(context, 2), identifier = "confirmed-ErrorPDU")]
        confirmed_ErrorPDU(ConfirmedErrorPDU),
        #[rasn(tag(context, 3), identifier = "unconfirmed-PDU")]
        unconfirmed_PDU(UnconfirmedPDU),
        #[rasn(tag(context, 4))]
        rejectPDU(RejectPDU),
        #[rasn(tag(context, 8), identifier = "initiate-RequestPDU")]
        initiate_RequestPDU(InitiateRequestPDU),
        #[rasn(tag(context, 9), identifier = "initiate-ResponsePDU")]
        initiate_ResponsePDU(InitiateResponsePDU),
        #[rasn(tag(context, 10), identifier = "initiate-ErrorPDU")]
        initiate_ErrorPDU(InitiateErrorPDU),
        #[rasn(tag(context, 11), identifier = "conclude-RequestPDU")]
        conclude_RequestPDU(ConcludeRequestPDU),
    }
    impl From<ConfirmedRequestPDU> for MMSpdu {
        fn from(value: ConfirmedRequestPDU) -> Self {
            Self::confirmed_RequestPDU(value)
        }
    }
    impl From<ConfirmedResponsePDU> for MMSpdu {
        fn from(value: ConfirmedResponsePDU) -> Self {
            Self::confirmed_ResponsePDU(value)
        }
    }
    impl From<ConfirmedErrorPDU> for MMSpdu {
        fn from(value: ConfirmedErrorPDU) -> Self {
            Self::confirmed_ErrorPDU(value)
        }
    }
    impl From<UnconfirmedPDU> for MMSpdu {
        fn from(value: UnconfirmedPDU) -> Self {
            Self::unconfirmed_PDU(value)
        }
    }
    impl From<RejectPDU> for MMSpdu {
        fn from(value: RejectPDU) -> Self {
            Self::rejectPDU(value)
        }
    }
    impl From<InitiateRequestPDU> for MMSpdu {
        fn from(value: InitiateRequestPDU) -> Self {
            Self::initiate_RequestPDU(value)
        }
    }
    impl From<InitiateResponsePDU> for MMSpdu {
        fn from(value: InitiateResponsePDU) -> Self {
            Self::initiate_ResponsePDU(value)
        }
    }
    impl From<InitiateErrorPDU> for MMSpdu {
        fn from(value: InitiateErrorPDU) -> Self {
            Self::initiate_ErrorPDU(value)
        }
    }
    impl From<ConcludeRequestPDU> for MMSpdu {
        fn from(value: ConcludeRequestPDU) -> Self {
            Self::conclude_RequestPDU(value)
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    pub enum ObjectClass {
        #[rasn(tag(context, 0))]
        basicObjectClass(Integer),
    }
    impl From<Integer> for ObjectClass {
        fn from(value: Integer) -> Self {
            Self::basicObjectClass(value)
        }
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct ObjectNameDomainSpecific {
        #[rasn(identifier = "domainID")]
        pub domain_id: Identifier,
        #[rasn(identifier = "itemID")]
        pub item_id: Identifier,
    }
    impl ObjectNameDomainSpecific {
        pub fn new(domain_id: Identifier, item_id: Identifier) -> Self {
            Self { domain_id, item_id }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    pub enum ObjectName {
        #[rasn(tag(context, 0), identifier = "vmd-specific")]
        vmd_specific(Identifier),
        #[rasn(tag(context, 1), identifier = "domain-specific")]
        domain_specific(ObjectNameDomainSpecific),
        #[rasn(tag(context, 2), identifier = "aa-specific")]
        aa_specific(Identifier),
    }
    impl From<ObjectNameDomainSpecific> for ObjectName {
        fn from(value: ObjectNameDomainSpecific) -> Self {
            Self::domain_specific(value)
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct ParameterSupportOptions(pub BitString);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "Read-Request")]
    pub struct ReadRequest {
        #[rasn(
            tag(context, 0),
            default = "read_request_specification_with_result_default",
            identifier = "specificationWithResult"
        )]
        pub specification_with_result: bool,
        #[rasn(tag(context, 1), identifier = "variableAccessSpecification")]
        pub variable_access_specification: VariableAccessSpecification,
    }
    impl ReadRequest {
        pub fn new(
            specification_with_result: bool,
            variable_access_specification: VariableAccessSpecification,
        ) -> Self {
            Self {
                specification_with_result,
                variable_access_specification,
            }
        }
    }
    fn read_request_specification_with_result_default() -> bool {
        false
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "Read-Response")]
    pub struct ReadResponse {
        #[rasn(tag(context, 0), identifier = "variableAccessSpecification")]
        pub variable_access_specification: Option<VariableAccessSpecification>,
        #[rasn(tag(context, 1), identifier = "listOfAccessResult")]
        pub list_of_access_result: SequenceOf<AccessResult>,
    }
    impl ReadResponse {
        pub fn new(
            variable_access_specification: Option<VariableAccessSpecification>,
            list_of_access_result: SequenceOf<AccessResult>,
        ) -> Self {
            Self {
                variable_access_specification,
                list_of_access_result,
            }
        }
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    pub enum RejectPDURejectReason {
        #[rasn(tag(context, 1), identifier = "confirmed-requestPDU")]
        confirmed_requestPDU(Integer),
        #[rasn(tag(context, 2), identifier = "confirmed-responsePDU")]
        confirmed_responsePDU(Integer),
        #[rasn(tag(context, 3), identifier = "confirmed-errorPDU")]
        confirmed_errorPDU(Integer),
        #[rasn(tag(context, 4))]
        unconfirmedPDU(Integer),
        #[rasn(tag(context, 5), identifier = "pdu-error")]
        pdu_error(Integer),
        #[rasn(tag(context, 6), identifier = "cancel-requestPDU")]
        cancel_requestPDU(Integer),
        #[rasn(tag(context, 7), identifier = "cancel-responsePDU")]
        cancel_responsePDU(Integer),
        #[rasn(tag(context, 8), identifier = "cancel-errorPDU")]
        cancel_errorPDU(Integer),
        #[rasn(tag(context, 9), identifier = "conclude-requestPDU")]
        conclude_requestPDU(Integer),
        #[rasn(tag(context, 10), identifier = "conclude-responsePDU")]
        conclude_responsePDU(Integer),
        #[rasn(tag(context, 11), identifier = "conclude-errorPDU")]
        conclude_errorPDU(Integer),
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct RejectPDU {
        #[rasn(tag(context, 0), identifier = "originalInvokeID")]
        pub original_invoke_id: Option<Unsigned32>,
        #[rasn(identifier = "rejectReason")]
        pub reject_reason: RejectPDURejectReason,
    }
    impl RejectPDU {
        pub fn new(
            original_invoke_id: Option<Unsigned32>,
            reject_reason: RejectPDURejectReason,
        ) -> Self {
            Self {
                original_invoke_id,
                reject_reason,
            }
        }
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    pub enum ServiceErrorErrorClass {
        #[rasn(tag(context, 0), identifier = "vmd-state")]
        vmd_state(Integer),
        #[rasn(tag(context, 1), identifier = "application-reference")]
        application_reference(Integer),
        #[rasn(tag(context, 2))]
        definition(Integer),
        #[rasn(tag(context, 3))]
        resource(Integer),
        #[rasn(tag(context, 4))]
        service(Integer),
        #[rasn(tag(context, 5), identifier = "service-preempt")]
        service_preempt(Integer),
        #[rasn(tag(context, 6), identifier = "time-resolution")]
        time_resolution(Integer),
        #[rasn(tag(context, 7))]
        access(Integer),
        #[rasn(tag(context, 8))]
        initiate(Integer),
        #[rasn(tag(context, 9))]
        conclude(Integer),
        #[rasn(tag(context, 10))]
        cancel(Integer),
        #[rasn(tag(context, 11))]
        file(Integer),
        #[rasn(tag(context, 12))]
        others(Integer),
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct ServiceError {
        #[rasn(tag(context, 0), identifier = "errorClass")]
        pub error_class: ServiceErrorErrorClass,
        #[rasn(tag(context, 1), identifier = "additionalCode")]
        pub additional_code: Option<Integer>,
        #[rasn(tag(context, 2), identifier = "additionalDescription")]
        pub additional_description: Option<VisibleString>,
    }
    impl ServiceError {
        pub fn new(
            error_class: ServiceErrorErrorClass,
            additional_code: Option<Integer>,
            additional_description: Option<VisibleString>,
        ) -> Self {
            Self {
                error_class,
                additional_code,
                additional_description,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct ServiceSupportOptions(pub BitString);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, size("4..=6"))]
    pub struct TimeOfDay(pub OctetString);
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct TypeSpecificationArray {
        #[rasn(tag(context, 0), default = "type_specification_array_packed_default")]
        pub packed: bool,
        #[rasn(tag(context, 1), identifier = "numberOfElements")]
        pub number_of_elements: Unsigned32,
        #[rasn(tag(context, 2), identifier = "elementType")]
        pub element_type: TypeSpecification,
    }
    impl TypeSpecificationArray {
        pub fn new(
            packed: bool,
            number_of_elements: Unsigned32,
            element_type: TypeSpecification,
        ) -> Self {
            Self {
                packed,
                number_of_elements,
                element_type,
            }
        }
    }
    fn type_specification_array_packed_default() -> bool {
        false
    }
    #[doc = " Anonymous SEQUENCE OF member "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "SEQUENCE")]
    pub struct AnonymousTypeSpecificationStructureComponents {
        #[rasn(tag(context, 0), identifier = "componentName")]
        pub component_name: Option<Identifier>,
        #[rasn(tag(context, 1), identifier = "componentType")]
        pub component_type: TypeSpecification,
    }
    impl AnonymousTypeSpecificationStructureComponents {
        pub fn new(component_name: Option<Identifier>, component_type: TypeSpecification) -> Self {
            Self {
                component_name,
                component_type,
            }
        }
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct TypeSpecificationStructureComponents(
        pub SequenceOf<AnonymousTypeSpecificationStructureComponents>,
    );
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct TypeSpecificationStructure {
        #[rasn(
            tag(context, 0),
            default = "type_specification_structure_packed_default"
        )]
        pub packed: bool,
        #[rasn(tag(context, 1))]
        pub components: TypeSpecificationStructureComponents,
    }
    impl TypeSpecificationStructure {
        pub fn new(packed: bool, components: TypeSpecificationStructureComponents) -> Self {
            Self { packed, components }
        }
    }
    fn type_specification_structure_packed_default() -> bool {
        false
    }
    #[doc = " Inner type "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    pub struct TypeSpecificationFloatingPoint {
        #[rasn(identifier = "format-width")]
        pub format_width: Unsigned8,
        #[rasn(identifier = "exponent-width")]
        pub exponent_width: Unsigned8,
    }
    impl TypeSpecificationFloatingPoint {
        pub fn new(format_width: Unsigned8, exponent_width: Unsigned8) -> Self {
            Self {
                format_width,
                exponent_width,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    pub enum TypeSpecification {
        #[rasn(tag(context, 1))]
        array(Box<TypeSpecificationArray>),
        #[rasn(tag(context, 2))]
        structure(TypeSpecificationStructure),
        #[rasn(tag(context, 3))]
        bool(()),
        #[rasn(tag(context, 4), identifier = "bit-string")]
        bit_string(Integer32),
        #[rasn(tag(context, 5))]
        integer(Unsigned8),
        #[rasn(tag(context, 6))]
        unsigned(Unsigned8),
        #[rasn(tag(context, 7), identifier = "floating-point")]
        floating_point(TypeSpecificationFloatingPoint),
        #[rasn(tag(context, 9), identifier = "octet-string")]
        octet_string(Integer32),
        #[rasn(tag(context, 10), identifier = "visible-string")]
        visible_string(Integer32),
        #[rasn(tag(context, 12), identifier = "binary-time")]
        binary_time(bool),
        #[rasn(tag(context, 16))]
        mMSString(Integer32),
        #[rasn(tag(context, 17), identifier = "utc-time")]
        utc_time(()),
    }
    impl From<Box<TypeSpecificationArray>> for TypeSpecification {
        fn from(value: Box<TypeSpecificationArray>) -> Self {
            Self::array(value)
        }
    }
    impl From<TypeSpecificationStructure> for TypeSpecification {
        fn from(value: TypeSpecificationStructure) -> Self {
            Self::structure(value)
        }
    }
    impl From<TypeSpecificationFloatingPoint> for TypeSpecification {
        fn from(value: TypeSpecificationFloatingPoint) -> Self {
            Self::floating_point(value)
        }
    }
    impl From<bool> for TypeSpecification {
        fn from(value: bool) -> Self {
            Self::binary_time(value)
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "Unconfirmed-PDU")]
    pub struct UnconfirmedPDU {
        pub service: UnconfirmedService,
    }
    impl UnconfirmedPDU {
        pub fn new(service: UnconfirmedService) -> Self {
            Self { service }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    pub enum UnconfirmedService {
        #[rasn(tag(context, 0))]
        informationReport(InformationReport),
    }
    impl From<InformationReport> for UnconfirmedService {
        fn from(value: InformationReport) -> Self {
            Self::informationReport(value)
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0..=65535"))]
    pub struct Unsigned16(pub u16);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0..=4294967295"))]
    pub struct Unsigned32(pub u32);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, value("0..=255"))]
    pub struct Unsigned8(pub u8);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct UtcTime(pub FixedOctetString<8usize>);
    #[doc = "{"]
    #[doc = "    object-invalidated (0),"]
    #[doc = "    hardware-fault (1),"]
    #[doc = "    temporarily-unavailable (2),"]
    #[doc = "    object-access-denied (3),"]
    #[doc = "    object-undefined (4),"]
    #[doc = "    invalid-address (5),"]
    #[doc = "    type-unsupported (6),"]
    #[doc = "    type-inconsistent (7),"]
    #[doc = "    object-attribute-inconsistent (8),"]
    #[doc = "    object-access-unsupported (9),"]
    #[doc = "    object-non-existent (10),"]
    #[doc = "    object-value-invalid (11)"]
    #[doc = "}"]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    pub enum VariableAccessSpecification {
        #[rasn(tag(context, 0))]
        listOfVariable(VariableDefs),
        #[rasn(tag(context, 1))]
        variableListName(ObjectName),
    }
    impl From<VariableDefs> for VariableAccessSpecification {
        fn from(value: VariableDefs) -> Self {
            Self::listOfVariable(value)
        }
    }
    impl From<ObjectName> for VariableAccessSpecification {
        fn from(value: ObjectName) -> Self {
            Self::variableListName(value)
        }
    }
    #[doc = " Anonymous SEQUENCE OF member "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "SEQUENCE")]
    pub struct AnonymousVariableDefs {
        #[rasn(identifier = "variableSpecification")]
        pub variable_specification: VariableSpecification,
        #[rasn(tag(context, 5), identifier = "alternateAccess")]
        pub alternate_access: Option<AlternateAccess>,
    }
    impl AnonymousVariableDefs {
        pub fn new(
            variable_specification: VariableSpecification,
            alternate_access: Option<AlternateAccess>,
        ) -> Self {
            Self {
                variable_specification,
                alternate_access,
            }
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate)]
    pub struct VariableDefs(pub SequenceOf<AnonymousVariableDefs>);
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice)]
    pub enum VariableSpecification {
        #[rasn(tag(context, 0))]
        name(ObjectName),
    }
    impl From<ObjectName> for VariableSpecification {
        fn from(value: ObjectName) -> Self {
            Self::name(value)
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(identifier = "Write-Request")]
    pub struct WriteRequest {
        #[rasn(identifier = "variableAccessSpecification")]
        pub variable_access_specification: VariableAccessSpecification,
        #[rasn(tag(context, 0), identifier = "listOfData")]
        pub list_of_data: SequenceOf<Data>,
    }
    impl WriteRequest {
        pub fn new(
            variable_access_specification: VariableAccessSpecification,
            list_of_data: SequenceOf<Data>,
        ) -> Self {
            Self {
                variable_access_specification,
                list_of_data,
            }
        }
    }
    #[doc = " Anonymous SEQUENCE OF member "]
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(choice, identifier = "CHOICE")]
    pub enum AnonymousWriteResponse {
        #[rasn(tag(context, 0))]
        failure(DataAccessError),
        #[rasn(tag(context, 1))]
        success(()),
    }
    impl From<DataAccessError> for AnonymousWriteResponse {
        fn from(value: DataAccessError) -> Self {
            Self::failure(value)
        }
    }
    impl From<()> for AnonymousWriteResponse {
        fn from(value: ()) -> Self {
            Self::success(value)
        }
    }
    #[derive(AsnType, Debug, Clone, Decode, Encode, PartialEq, Eq, Hash)]
    #[rasn(delegate, identifier = "Write-Response")]
    pub struct WriteResponse(pub SequenceOf<AnonymousWriteResponse>);
}
