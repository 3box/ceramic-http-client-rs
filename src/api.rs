use crate::query::FilterQuery;
use ceramic_event::{
    Base64String, Base64UrlString, Jws, MultiBase32String, MultiBase36String, StreamId,
    StreamIdType,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Header for block data
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeader {
    /// Family that block belongs to
    pub family: String,
    /// Controllers for block
    pub controllers: Vec<String>,
    /// Model for block
    pub model: Base64String,
}

/// Block data
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockData<T: Serialize> {
    /// Header for block
    pub header: BlockHeader,
    /// Data for block
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    /// Signature for block
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jws: Option<Jws>,
    /// IPFS Linked Block
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linked_block: Option<Base64String>,
    /// Related cacao block
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cacao_block: Option<MultiBase32String>,
}

/// Create request for http api
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateRequest<T: Serialize> {
    /// Type of stream to create
    #[serde(rename = "type")]
    pub r#type: StreamIdType,
    /// Data to use when creating stream
    #[serde(rename = "genesis")]
    pub block: BlockData<T>,
}

/// Update request for http api
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRequest {
    /// Type of stream to update
    #[serde(rename = "type")]
    pub r#type: StreamIdType,
    /// Data to update stream to
    #[serde(rename = "commit")]
    pub block: BlockData<Base64String>,
    /// Stream to update
    pub stream_id: MultiBase36String,
}

/// Log entry for stream
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StateLog {
    /// CID for stream
    pub cid: MultiBase36String,
}

/// Metadata for stream
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    /// Controllers for stream
    pub controllers: Vec<String>,
    /// Model for stream
    pub model: StreamId,
}

/// Current state of stream
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamState {
    /// Content of stream
    pub content: Value,
    /// Log of stream
    pub log: Vec<StateLog>,
    /// Metadata for stream
    pub metadata: Metadata,
}

/// Response from request against streams endpoint
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamsResponse {
    /// ID of stream requested
    pub stream_id: StreamId,
    /// State of stream
    pub state: Option<StreamState>,
}

/// Response from request against streams endpoint or error
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum StreamsResponseOrError {
    /// Response was an error
    Error {
        /// Error message
        error: String,
    },
    /// Response was ok
    Ok(StreamsResponse),
}

impl StreamsResponseOrError {
    /// Resolve or throw error from response
    pub fn resolve(self, context: &str) -> anyhow::Result<StreamsResponse> {
        match self {
            Self::Error { error } => {
                anyhow::bail!(format!("{}: {}", context, error))
            }
            Self::Ok(resp) => Ok(resp),
        }
    }
}

/// Json wrapper around jws
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JwsValue {
    /// Jws for a specific commit
    pub jws: Jws,
}

/// Commit for a specific stream
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Commit {
    /// Commit id
    pub cid: MultiBase36String,
    /// Value of commit
    pub value: Option<JwsValue>,
}

/// Response from commits endpoint
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitsResponse {
    /// ID of stream for commit
    pub stream_id: StreamId,
    /// Commits of stream
    pub commits: Vec<Commit>,
}

/// Model data for indexing
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelData {
    /// Model id to index
    #[serde(rename = "streamID")]
    pub model: StreamId,
}

/// Model data for indexing
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexModelData {
    /// Models to index
    #[serde(rename = "modelData")]
    pub models: Vec<ModelData>,
}

/// Response from call to admin api /getCode
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminCodeResponse {
    /// Generated code
    pub code: String,
}

/// JWS Info for Admin request
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminApiPayload<T: Serialize> {
    /// Admin access code from /getCode request
    pub code: String,
    /// Admin path request is against
    pub request_path: String,
    /// Body of request
    pub request_body: T,
}

/// Request against admin api
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminApiRequest {
    jws: String,
}

impl TryFrom<Jws> for AdminApiRequest {
    type Error = anyhow::Error;
    fn try_from(value: Jws) -> Result<Self, Self::Error> {
        let maybe_sig = value
            .signatures
            .first()
            .and_then(|sig| sig.protected.as_ref().map(|p| (&sig.signature, p)));
        if let Some((sig, protected)) = &maybe_sig {
            let sig = format!("{}.{}.{}", protected, value.payload, sig);
            Ok(Self { jws: sig })
        } else {
            anyhow::bail!("Invalid jws, no signatures")
        }
    }
}

/// Pagination for query
#[derive(Debug, Serialize)]
#[serde(untagged, rename_all = "camelCase")]
pub enum Pagination {
    /// Paginate forward
    First {
        /// Number of results to return
        first: u32,
        /// Point to start query from
        #[serde(skip_serializing_if = "Option::is_none")]
        after: Option<Base64UrlString>,
    },
    /// Paginate backwards
    Last {
        /// Number of results to return
        last: u32,
        /// Point to start query from
        #[serde(skip_serializing_if = "Option::is_none")]
        before: Option<Base64UrlString>,
    },
}

impl Default for Pagination {
    fn default() -> Self {
        Self::First {
            first: 100,
            after: None,
        }
    }
}

/// Request to query
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryRequest {
    /// Model to query documents for
    pub model: StreamId,
    /// Account making query
    pub account: String,
    /// Filters to use
    #[serde(rename = "queryFilters", skip_serializing_if = "Option::is_none")]
    pub query: Option<FilterQuery>,
    /// Pagination
    #[serde(flatten)]
    pub pagination: Pagination,
}

/// Node returned from query
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryNode {
    /// Content of node
    pub content: Value,
    /// Commits for stream
    pub log: Vec<Commit>,
}

/// Edge returned from query
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryEdge {
    /// Cursor for edge
    pub cursor: Base64UrlString,
    /// Underlying node
    pub node: QueryNode,
}

/// Info about query pages
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PageInfo {
    /// Whether next page exists
    pub has_next_page: bool,
    /// Whether previous page exists
    pub has_previous_page: bool,
    /// Cursor for next page
    pub end_cursor: Base64UrlString,
    /// Cursor for previous page
    pub start_cursor: Base64UrlString,
}

/// Response to query
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryResponse {
    /// Edges of query
    pub edges: Vec<QueryEdge>,
    /// Pagination info
    pub page_info: PageInfo,
}

/// Typed response to query
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypedQueryDocument<T> {
    /// Document extracted from content
    pub document: T,
    /// All commits for underlying stream
    pub commits: Vec<Commit>,
}

/// Typed response to query
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TypedQueryResponse<T> {
    /// Documents from query
    pub documents: Vec<TypedQueryDocument<T>>,
    /// Pagination info
    pub page_info: PageInfo,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OperationFilter;
    use std::collections::HashMap;
    use std::str::FromStr;

    #[test]
    fn should_serialize_query_request() {
        let mut where_filter = HashMap::new();
        where_filter.insert(
            "id".to_string(),
            OperationFilter::EqualTo("1".to_string().into()),
        );
        let filter = FilterQuery::Where(where_filter);
        let req = QueryRequest {
            model: StreamId::from_str(
                "kjzl6hvfrbw6c8apa5yce6ah3fsz9sgrh6upniy0tz8z76gdm169ds3tf8c051t",
            )
            .unwrap(),
            account: "test".to_string(),
            query: Some(filter),
            pagination: Pagination::default(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            &json,
            r#"{"model":"kjzl6hvfrbw6c8apa5yce6ah3fsz9sgrh6upniy0tz8z76gdm169ds3tf8c051t","account":"test","queryFilters":{"where":{"id":{"equalTo":"1"}}},"first":100}"#
        );
    }
}
