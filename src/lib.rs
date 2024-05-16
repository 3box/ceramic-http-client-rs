//! Ceramic HTTP API
//!
//! This crate provides a client for interacting with the Ceramic HTTP API.
#![deny(warnings)]
#![deny(missing_docs)]
/// Structures for working with ceramic http api
pub mod api;
mod model_definition;
mod query;

use ceramic_event::{
    event_builder::*,
    unvalidated::{self, IntoSignedCeramicEvent},
    Base64String, Cid, EventBytes, Jws, MultiBase36String, Signer, StreamId, StreamIdType,
};
use serde::Serialize;
use std::str::FromStr;

use crate::api::{ModelData, PARENT_STREAM_ID, SEP};
pub use ceramic_event;
pub use json_patch;
pub use model_definition::{
    GetRootSchema, ModelAccountRelation, ModelDefinition, ModelRelationDefinition,
    ModelViewDefinition,
};
pub use query::*;
pub use schemars;

/// Client for interacting with the Ceramic HTTP API
#[derive(Clone, Debug)]
pub struct CeramicHttpClient<S> {
    signer: S,
}

const FAMILY: &str = "rust-client";

impl<S: Signer + Sync> CeramicHttpClient<S> {
    /// Create a new client, using a signer and private key
    pub fn new(signer: S) -> Self {
        Self { signer }
    }

    /// Get the signer for this client
    pub fn signer(&self) -> &S {
        &self.signer
    }

    /// Get the streams endpoint
    pub fn streams_endpoint(&self) -> &'static str {
        "/api/v0/streams"
    }

    /// Get the commits endpoint
    pub fn commits_endpoint(&self) -> &'static str {
        "/api/v0/commits"
    }

    /// Get the collection endpoint
    pub fn collection_endpoint(&self) -> &'static str {
        "/api/v0/collection"
    }

    /// Get the code endpoint
    pub fn admin_code_endpoint(&self) -> &'static str {
        "/api/v0/admin/getCode"
    }

    /// Get the index endpoint
    pub fn index_endpoint(&self) -> &'static str {
        "/api/v0/admin/modelData"
    }
    /// Get the models endpoint
    pub fn models_endpoint(&self) -> &'static str {
        "/api/v0/admin/models"
    }

    /// Get the healthcheck endpoint
    pub fn healthcheck_endpoint(&self) -> &'static str {
        "/api/v0/node/healthcheck"
    }

    /// Get the status endpoint
    pub fn node_status_endpoint(&self) -> &'static str {
        "/api/v0/admin/status"
    }

    /// Create a serde compatible request for model creation
    pub async fn create_model_request(
        &self,
        model: &ModelDefinition,
    ) -> anyhow::Result<api::CreateRequest<Base64String>> {
        let controller = self.signer.id().id.clone();
        let parent: EventBytes = PARENT_STREAM_ID.to_vec()?.into();
        let commit = Builder::default()
            .with_sep(SEP.to_string())
            .with_additional(SEP.to_string(), parent.into())
            .init()
            .with_controller(controller.clone())
            .with_data(&model)
            .build()
            .await?;
        let commit: unvalidated::Payload<_> = commit.into();
        let commit = commit.signed(&self.signer).await?;
        let controllers: Vec<_> = vec![controller];
        let data = Base64String::from(commit.linked_block.as_ref());
        let model = Base64String::from(PARENT_STREAM_ID.to_vec()?);

        Ok(api::CreateRequest {
            r#type: StreamIdType::Model,
            block: api::BlockData {
                header: api::BlockHeader {
                    family: FAMILY.to_string(),
                    controllers,
                    model,
                },
                linked_block: Some(data.clone()),
                jws: Some(commit.jws),
                data: Some(data),
                cacao_block: None,
            },
        })
    }

    /// Create a serde compatible request for model indexing
    pub async fn create_index_model_request(
        &self,
        model_id: &StreamId,
        code: &str,
    ) -> anyhow::Result<api::AdminApiRequest> {
        let data = api::IndexModelData {
            models: vec![ModelData {
                model: model_id.clone(),
            }],
        };
        let req = api::AdminApiPayload {
            code: code.to_string(),
            request_path: self.index_endpoint().to_string(),
            request_body: data,
        };
        let jws = Jws::builder(&self.signer).build_for_data(&req).await?;
        api::AdminApiRequest::try_from(jws)
    }

    /// Create a serde compatible request for listing indexed models
    pub async fn create_list_indexed_models_request(
        &self,
        code: &str,
    ) -> anyhow::Result<api::AdminApiRequest> {
        let data = api::ListIndexedModelsRequest {};
        let req = api::AdminApiPayload {
            code: code.to_string(),
            request_path: self.models_endpoint().to_string(),
            request_body: data,
        };
        let jws = Jws::builder(&self.signer).build_for_data(&req).await?;
        api::AdminApiRequest::try_from(jws)
    }

    /// Create a serde compatible request for a single instance per account creation of a model
    pub async fn create_single_instance_request(
        &self,
        model_id: &StreamId,
    ) -> anyhow::Result<api::CreateRequest<()>> {
        if !model_id.is_model() {
            anyhow::bail!("StreamId was not a model");
        }
        let controllers: Vec<_> = vec![self.signer.id().id.clone()];
        let model = Base64String::from(model_id.to_vec()?);
        Ok(api::CreateRequest {
            r#type: StreamIdType::ModelInstanceDocument,
            block: api::BlockData {
                header: api::BlockHeader {
                    family: FAMILY.to_string(),
                    controllers,
                    model,
                },
                linked_block: None,
                jws: None,
                data: None,
                cacao_block: None,
            },
        })
    }

    fn gen_rand_bytes<const SIZE: usize>() -> [u8; SIZE] {
        // can't take &mut rng cause of Send even if we drop it
        let mut rng = rand::thread_rng();
        let mut arr = [0; SIZE];
        for x in &mut arr {
            *x = rand::Rng::gen_range(&mut rng, 0..=255);
        }
        arr
    }

    /// Create a serde compatible request for a list instance per account creation of a model
    pub async fn create_list_instance_request<T: Serialize + Send>(
        &self,
        model_id: &StreamId,
        data: T,
    ) -> anyhow::Result<api::CreateRequest<Base64String>> {
        if !model_id.is_model() {
            anyhow::bail!("StreamId was not a model");
        }
        let model_vec = model_id.to_vec()?;
        let model = Base64String::from(model_vec.as_slice());
        let model_bytes = EventBytes::from(model_vec);
        let unique = Self::gen_rand_bytes::<12>();
        let unique: EventBytes = unique.to_vec().into();
        let controller = self.signer.id().id.clone();
        let commit = Builder::default()
            .with_sep(SEP.to_string())
            .with_additional(SEP.to_string(), model_bytes.into())
            .with_additional("unique".to_string(), unique.into())
            .init()
            .with_controller(controller.clone())
            .with_data(data)
            .build()
            .await?;
        let commit: unvalidated::Payload<_> = commit.into();
        let commit = commit.signed(&self.signer).await?;
        let controllers: Vec<_> = vec![controller];
        let data = Base64String::from(commit.linked_block.as_ref());

        Ok(api::CreateRequest {
            r#type: StreamIdType::ModelInstanceDocument,
            block: api::BlockData {
                header: api::BlockHeader {
                    family: FAMILY.to_string(),
                    controllers,
                    model,
                },
                linked_block: Some(data.clone()),
                jws: Some(commit.jws),
                data: Some(data),
                cacao_block: None,
            },
        })
    }

    /// Create a serde compatible request to update specific parts an existing model instance
    pub async fn create_update_request(
        &self,
        model: &StreamId,
        get: &api::StreamsResponse,
        patch: json_patch::Patch,
    ) -> anyhow::Result<api::UpdateRequest> {
        if !get.stream_id.is_document() {
            anyhow::bail!("StreamId was not a document");
        }
        if let Some(tip) = get.state.as_ref().and_then(|s| s.log.last()) {
            let tip = Cid::from_str(tip.cid.as_ref())?;
            let controller = self.signer.id().id.clone();
            let model_vec = model.to_vec()?;
            let model = Base64String::from(model_vec.as_slice());
            let commit = Builder::default()
                .data(get.stream_id.cid, tip, patch)
                .build()
                .await?;
            let commit: unvalidated::Payload<_> = commit.into();
            let commit = commit.signed(&self.signer).await?;
            let controllers: Vec<_> = vec![controller];
            let data = Base64String::from(commit.linked_block.as_ref());
            let stream = MultiBase36String::try_from(&get.stream_id)?;
            Ok(api::UpdateRequest {
                r#type: StreamIdType::ModelInstanceDocument,
                block: api::BlockData {
                    header: api::BlockHeader {
                        family: FAMILY.to_string(),
                        controllers,
                        model,
                    },
                    linked_block: Some(data.clone()),
                    jws: Some(commit.jws),
                    data: Some(data),
                    cacao_block: None,
                },
                stream_id: stream,
            })
        } else {
            Err(anyhow::anyhow!("No commits found for stream ",))
        }
    }

    /// Create a serde compatible request to replace an existing model instance completely
    pub async fn create_replace_request<T: Serialize>(
        &self,
        model: &StreamId,
        get: &api::StreamsResponse,
        data: T,
    ) -> anyhow::Result<api::UpdateRequest> {
        let data = serde_json::to_value(data)?;
        let diff = if let Some(existing) = get.state.as_ref().map(|st| &st.content) {
            json_patch::diff(existing, &data)
        } else {
            json_patch::diff(&serde_json::json!({}), &data)
        };
        self.create_update_request(model, get, diff).await
    }

    /// Create a serde compatible request to query model instances
    pub async fn create_query_request(
        &self,
        model: &StreamId,
        query: Option<FilterQuery>,
        pagination: api::Pagination,
    ) -> anyhow::Result<api::QueryRequest> {
        Ok(api::QueryRequest {
            model: model.clone(),
            account: self.signer.id().id.clone(),
            query,
            pagination,
        })
    }

    /// Create a serde compatible request to check node health
    pub async fn create_healthcheck_request(&self) -> anyhow::Result<api::HealthcheckRequest> {
        Ok(api::HealthcheckRequest {})
    }
    /// Create a serde compatible request for the node status
    pub async fn create_node_status_request(
        &self,
        code: &str,
    ) -> anyhow::Result<api::AdminApiRequest> {
        let data = api::NodeStatusRequest {};
        let req = api::AdminApiPayload {
            code: code.to_string(),
            request_path: self.node_status_endpoint().to_string(),
            request_body: data,
        };
        let jws = Jws::builder(&self.signer).build_for_data(&req).await?;
        api::AdminApiRequest::try_from(jws)
    }
}

/// Remote HTTP Functionality
#[cfg(feature = "remote")]
pub mod remote {
    use super::*;
    use crate::api::Pagination;
    use crate::query::FilterQuery;
    use serde::de::DeserializeOwned;
    pub use url::{ParseError, Url};

    #[derive(Clone)]
    /// Ceramic remote http client
    pub struct CeramicRemoteHttpClient<S> {
        cli: CeramicHttpClient<S>,
        remote: reqwest::Client,
        url: Url,
    }

    impl<S: Signer + Sync> CeramicRemoteHttpClient<S> {
        /// Create a new ceramic remote http client for a signer, private key, and url
        pub fn new(signer: S, remote: Url) -> Self {
            Self {
                cli: CeramicHttpClient::new(signer),
                remote: reqwest::Client::new(),
                url: remote,
            }
        }

        /// Access the underlying client
        pub fn client(&self) -> &CeramicHttpClient<S> {
            &self.cli
        }

        /// Utility function to get a url for this client's base url, given a path
        pub fn url_for_path(&self, path: &str) -> anyhow::Result<url::Url> {
            let u = self.url.join(path)?;
            Ok(u)
        }

        /// Create a model on the remote ceramic
        pub async fn create_model(&self, model: &ModelDefinition) -> anyhow::Result<StreamId> {
            let req = self.cli.create_model_request(model).await?;
            let resp: api::StreamsResponseOrError = self
                .remote
                .post(self.url_for_path(self.cli.streams_endpoint())?)
                .json(&req)
                .send()
                .await?
                .json()
                .await?;
            Ok(resp.resolve("create_model")?.stream_id)
        }

        /// Index a model on the remote ceramic
        pub async fn index_model(&self, model_id: &StreamId) -> anyhow::Result<()> {
            let resp: api::AdminCodeResponse = self
                .remote
                .get(self.url_for_path(self.cli.admin_code_endpoint())?)
                .send()
                .await?
                .json()
                .await?;
            let req = self
                .cli
                .create_index_model_request(model_id, &resp.code)
                .await?;
            let resp = self
                .remote
                .post(self.url_for_path(self.cli.index_endpoint())?)
                .json(&req)
                .send()
                .await?;
            if resp.status().is_success() {
                Ok(())
            } else {
                anyhow::bail!("{}", resp.text().await?);
            }
        }

        /// List indexed models on the remote ceramic
        pub async fn list_indexed_models(&self) -> anyhow::Result<api::ListIndexedModelsResponse> {
            let resp: api::AdminCodeResponse = self
                .remote
                .get(self.url_for_path(self.cli.admin_code_endpoint())?)
                .send()
                .await?
                .json()
                .await?;
            let req = self
                .cli
                .create_list_indexed_models_request(&resp.code)
                .await?;
            let resp = self
                .remote
                .get(self.url_for_path(self.cli.models_endpoint())?)
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("Basic {}", req.jws()),
                )
                .send()
                .await?
                .json()
                .await?;
            Ok(resp)
        }

        /// Create an instance of a model that allows a single instance on the remote ceramic
        pub async fn create_single_instance(
            &self,
            model_id: &StreamId,
        ) -> anyhow::Result<StreamId> {
            let req = self.cli.create_single_instance_request(model_id).await?;
            let resp: api::StreamsResponseOrError = self
                .remote
                .post(self.url_for_path(self.cli.streams_endpoint())?)
                .json(&req)
                .send()
                .await?
                .json()
                .await?;
            Ok(resp.resolve("create_single_instance")?.stream_id)
        }

        /// Create an instance of a model allowing multiple instances on a remote ceramic
        pub async fn create_list_instance<T: Serialize + Send>(
            &self,
            model_id: &StreamId,
            instance: T,
        ) -> anyhow::Result<StreamId> {
            let req = self
                .cli
                .create_list_instance_request(model_id, instance)
                .await?;
            let resp: api::StreamsResponseOrError = self
                .remote
                .post(self.url_for_path(self.cli.streams_endpoint())?)
                .json(&req)
                .send()
                .await?
                .json()
                .await?;
            let resp = resp.resolve("create_list_instance")?;
            Ok(resp.stream_id)
        }

        /// Update an instance that was previously created
        pub async fn update(
            &self,
            model: &StreamId,
            stream_id: &StreamId,
            patch: json_patch::Patch,
        ) -> anyhow::Result<api::StreamsResponse> {
            let resp = self.get(stream_id).await?;
            let req = self.cli.create_update_request(model, &resp, patch).await?;
            let resp: api::StreamsResponseOrError = self
                .remote
                .post(self.url_for_path(self.cli.commits_endpoint())?)
                .json(&req)
                .send()
                .await?
                .json()
                .await?;
            resp.resolve("update")
        }

        /// Replace an instance that was previously created
        pub async fn replace<T: Serialize>(
            &self,
            model: &StreamId,
            stream_id: &StreamId,
            data: T,
        ) -> anyhow::Result<api::StreamsResponse> {
            let resp = self.get(stream_id).await?;
            let req = self.cli.create_replace_request(model, &resp, data).await?;
            let resp: api::StreamsResponseOrError = self
                .remote
                .post(self.url_for_path(self.cli.commits_endpoint())?)
                .json(&req)
                .send()
                .await?
                .json()
                .await?;
            resp.resolve("replace")
        }

        /// Get an instance of model
        pub async fn get(&self, stream_id: &StreamId) -> anyhow::Result<api::StreamsResponse> {
            let endpoint = format!("{}/{}", self.cli.streams_endpoint(), stream_id);
            let endpoint = self.url_for_path(&endpoint)?;
            let resp: api::StreamsResponse = self.remote.get(endpoint).send().await?.json().await?;
            Ok(resp)
        }

        /// Get the content of an instance of a model as a serde compatible type
        pub async fn get_as<T: DeserializeOwned>(&self, stream_id: &StreamId) -> anyhow::Result<T> {
            let resp = self.get(stream_id).await?;
            if let Some(st) = resp.state {
                let resp = serde_json::from_value(st.content)?;
                Ok(resp)
            } else {
                Err(anyhow::anyhow!("No commits for stream {}", stream_id))
            }
        }

        /// Query for documents, optionally matching a filter
        pub async fn query(
            &self,
            model_id: &StreamId,
            query: Option<FilterQuery>,
            pagination: Pagination,
        ) -> anyhow::Result<api::QueryResponse> {
            let req = self
                .cli
                .create_query_request(model_id, query, pagination)
                .await?;
            let endpoint = self.url_for_path(self.cli.collection_endpoint())?;
            let resp = self
                .remote
                .post(endpoint)
                .json(&req)
                .send()
                .await?
                .json()
                .await?;
            Ok(resp)
        }

        /// Query for documents matching a filter, deserialized to a serde compatible type
        pub async fn query_as<T: DeserializeOwned>(
            &self,
            model_id: &StreamId,
            query: Option<FilterQuery>,
            pagination: Pagination,
        ) -> anyhow::Result<api::TypedQueryResponse<T>> {
            let resp = self.query(model_id, query, pagination).await?;
            let try_docs: Result<Vec<_>, _> = resp
                .edges
                .into_iter()
                .map(|edge| {
                    serde_json::from_value(edge.node.content).map(|doc| api::TypedQueryDocument {
                        document: doc,
                        commits: edge.node.log,
                    })
                })
                .collect();
            Ok(api::TypedQueryResponse {
                documents: try_docs?,
                page_info: resp.page_info,
            })
        }

        /// Check Ceramic node health
        pub async fn healthcheck(&self) -> anyhow::Result<String> {
            let req = self.cli.create_healthcheck_request().await?;
            let resp = self
                .remote
                .get(self.url_for_path(self.cli.healthcheck_endpoint())?)
                .json(&req)
                .send()
                .await?
                .text()
                .await?;
            Ok(resp)
        }

        /// Get the node status
        pub async fn node_status(&self) -> anyhow::Result<api::NodeStatusResponse> {
            let resp: api::AdminCodeResponse = self
                .remote
                .get(self.url_for_path(self.cli.admin_code_endpoint())?)
                .send()
                .await?
                .json()
                .await?;
            let req = self.cli.create_node_status_request(&resp.code).await?;
            let resp = self
                .remote
                .get(self.url_for_path(self.cli.node_status_endpoint())?)
                .header(
                    reqwest::header::AUTHORIZATION,
                    format!("Basic {}", req.jws()),
                )
                .send()
                .await?
                .json()
                .await?;
            Ok(resp)
        }
    }
}

#[cfg(all(test, feature = "remote"))]
pub mod tests {
    use super::remote::*;
    use super::*;
    use crate::api::Pagination;
    use crate::model_definition::{GetRootSchema, ModelAccountRelation, ModelDefinition};
    use crate::query::{FilterQuery, OperationFilter};
    use ceramic_event::{DidDocument, JwkSigner};
    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::time::Duration;

    // See https://github.com/ajv-validator/ajv-formats for information on valid formats
    #[derive(Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
    #[schemars(rename_all = "camelCase", deny_unknown_fields)]
    struct Ball {
        creator: String,
        unique: String,
        radius: i32,
        red: i32,
        green: i32,
        blue: i32,
    }

    impl GetRootSchema for Ball {}

    pub fn ceramic_url() -> url::Url {
        let u =
            std::env::var("CERAMIC_URL").unwrap_or_else(|_| "http://localhost:7007".to_string());
        url::Url::parse(&u).unwrap()
    }

    pub async fn signer() -> JwkSigner {
        let s = std::env::var("DID_DOCUMENT").unwrap_or_else(|_| {
            "did:key:z6MkeqCTPhHPVg3HaAAtsR7vZ6FXkAHPXEbTJs7Y4CQABV9Z".to_string()
        });
        JwkSigner::new(
            DidDocument::new(&s),
            &std::env::var("DID_PRIVATE_KEY").unwrap(),
        )
        .await
        .unwrap()
    }

    pub async fn create_model(cli: &CeramicRemoteHttpClient<JwkSigner>) -> StreamId {
        let model = ModelDefinition::new::<Ball>("TestBall", ModelAccountRelation::List).unwrap();
        cli.create_model(&model).await.unwrap()
    }

    pub async fn create_single_model(cli: &CeramicRemoteHttpClient<JwkSigner>) -> StreamId {
        let model = ModelDefinition::new::<Ball>("TestBall", ModelAccountRelation::Single).unwrap();
        cli.create_model(&model).await.unwrap()
    }

    #[tokio::test]
    async fn should_create_model() {
        let ceramic = CeramicRemoteHttpClient::new(signer().await, ceramic_url());
        let model = ModelDefinition::new::<Ball>("TestBall", ModelAccountRelation::List).unwrap();
        ceramic.create_model(&model).await.unwrap();
    }

    #[tokio::test]
    async fn should_create_single_instance() {
        let ceramic = CeramicRemoteHttpClient::new(signer().await, ceramic_url());
        let model = create_single_model(&ceramic).await;
        ceramic.create_single_instance(&model).await.unwrap();
    }

    #[tokio::test]
    async fn should_create_and_update_single_instance() {
        let ceramic = CeramicRemoteHttpClient::new(signer().await, ceramic_url());
        let model = create_single_model(&ceramic).await;
        let stream_id = ceramic.create_single_instance(&model).await.unwrap();

        tokio::time::sleep(Duration::from_secs(1)).await;

        let patch: json_patch::Patch = serde_json::from_value(serde_json::json!([
            { "op": "add", "path": "/creator", "value": ceramic.client().signer().id().id },
            { "op": "add", "path": "/unique", "value": "should_create_and_update_single_instance" },
            { "op": "add", "path": "/radius", "value": 1 },
            { "op": "add", "path": "/red", "value": 2 },
            { "op": "add", "path": "/green", "value": 3 },
            { "op": "add", "path": "/blue", "value": 4 },
        ]))
        .unwrap();
        let post_resp = ceramic.update(&model, &stream_id, patch).await.unwrap();
        assert_eq!(post_resp.stream_id, stream_id);
        let post_resp: Ball = serde_json::from_value(post_resp.state.unwrap().content).unwrap();
        assert_eq!(post_resp.red, 2);
    }

    #[tokio::test]
    async fn should_create_and_update_list() {
        let ceramic = CeramicRemoteHttpClient::new(signer().await, ceramic_url());
        let model = create_model(&ceramic).await;
        let stream_id = ceramic
            .create_list_instance(
                &model,
                &Ball {
                    creator: ceramic.client().signer().id().id.clone(),
                    unique: "should_create_and_update_list".to_string(),
                    radius: 1,
                    red: 2,
                    green: 3,
                    blue: 4,
                },
            )
            .await
            .unwrap();

        //give anchor time to complete
        tokio::time::sleep(Duration::from_secs(1)).await;

        let patch: json_patch::Patch = serde_json::from_value(serde_json::json!([
            { "op": "replace", "path": "/red", "value": 5 },
        ]))
        .unwrap();
        let post_resp = ceramic.update(&model, &stream_id, patch).await.unwrap();
        assert_eq!(post_resp.stream_id, stream_id);
        let post_resp: Ball = serde_json::from_value(post_resp.state.unwrap().content).unwrap();
        assert_eq!(post_resp.red, 5);

        //give anchor time to complete
        tokio::time::sleep(Duration::from_secs(1)).await;

        let patch: json_patch::Patch = serde_json::from_value(serde_json::json!([
            { "op": "replace", "path": "/blue", "value": 8 },
        ]))
        .unwrap();
        let post_resp = ceramic.update(&model, &stream_id, patch).await.unwrap();
        assert_eq!(post_resp.stream_id, stream_id);
        let post_resp: Ball = serde_json::from_value(post_resp.state.unwrap().content).unwrap();
        assert_eq!(post_resp.blue, 8);

        //give anchor time to complete
        tokio::time::sleep(Duration::from_secs(1)).await;

        let get_resp: Ball = ceramic.get_as(&stream_id).await.unwrap();
        assert_eq!(get_resp.red, 5);
        assert_eq!(get_resp.blue, 8);
        assert_eq!(get_resp, post_resp);
    }

    #[tokio::test]
    async fn should_create_and_replace_list() {
        let ceramic = CeramicRemoteHttpClient::new(signer().await, ceramic_url());
        let model = create_model(&ceramic).await;
        let stream_id = ceramic
            .create_list_instance(
                &model,
                &Ball {
                    creator: ceramic.client().signer().id().id.clone(),
                    unique: "should_create_and_replace_list".to_string(),
                    radius: 1,
                    red: 2,
                    green: 3,
                    blue: 4,
                },
            )
            .await
            .unwrap();

        //give anchor time to complete
        tokio::time::sleep(Duration::from_secs(1)).await;

        let replace = Ball {
            creator: ceramic.client().signer().id().id.clone(),
            unique: "should_create_and_replace_list".to_string(),
            radius: 1,
            red: 5,
            green: 3,
            blue: 4,
        };

        let post_resp = ceramic.replace(&model, &stream_id, &replace).await.unwrap();
        assert_eq!(post_resp.stream_id, stream_id);
        let post_resp: Ball = serde_json::from_value(post_resp.state.unwrap().content).unwrap();
        assert_eq!(post_resp, replace);

        //give anchor time to complete
        tokio::time::sleep(Duration::from_secs(1)).await;

        let replace = Ball {
            creator: ceramic.client().signer().id().id.clone(),
            unique: "should_create_and_replace_list".to_string(),
            radius: 1,
            red: 0,
            green: 3,
            blue: 10,
        };
        let post_resp = ceramic.replace(&model, &stream_id, &replace).await.unwrap();
        assert_eq!(post_resp.stream_id, stream_id);
        let post_resp: Ball = serde_json::from_value(post_resp.state.unwrap().content).unwrap();
        assert_eq!(post_resp, replace);

        //give anchor time to complete
        tokio::time::sleep(Duration::from_secs(1)).await;

        let get_resp: Ball = ceramic.get_as(&stream_id).await.unwrap();
        assert_eq!(get_resp, post_resp);
    }

    #[tokio::test]
    async fn should_query_models() {
        let ceramic = CeramicRemoteHttpClient::new(signer().await, ceramic_url());
        let model = create_model(&ceramic).await;
        ceramic.index_model(&model).await.unwrap();
        let _instance1 = ceramic
            .create_list_instance(
                &model,
                &Ball {
                    creator: ceramic.client().signer().id().id.clone(),
                    unique: "should_query_models".to_string(),
                    radius: 1,
                    red: 2,
                    green: 3,
                    blue: 4,
                },
            )
            .await
            .unwrap();

        let _instance2 = ceramic
            .create_list_instance(
                &model,
                &Ball {
                    creator: ceramic.client().signer().id().id.clone(),
                    unique: "should_query_models".to_string(),
                    radius: 2,
                    red: 3,
                    green: 4,
                    blue: 5,
                },
            )
            .await
            .unwrap();

        let mut where_filter = HashMap::new();
        where_filter.insert(
            "unique".to_string(),
            OperationFilter::EqualTo("should_query_models".into()),
        );
        where_filter.insert("blue".to_string(), OperationFilter::EqualTo(5.into()));
        let filter = FilterQuery::Where(where_filter);
        let res = ceramic
            .query(&model, Some(filter), Pagination::default())
            .await
            .unwrap();
        assert_eq!(res.edges.len(), 1);
        let node = &res.edges[0].node;
        let result: Ball = serde_json::from_value(node.content.clone()).unwrap();
        assert_eq!(result.blue, 5);
    }

    #[tokio::test]
    async fn should_query_models_after_update() {
        let ceramic = CeramicRemoteHttpClient::new(signer().await, ceramic_url());
        let model = create_model(&ceramic).await;
        ceramic.index_model(&model).await.unwrap();
        let _instance1 = ceramic
            .create_list_instance(
                &model,
                &Ball {
                    creator: ceramic.client().signer().id().id.clone(),
                    unique: "should_query_models_after_update".to_string(),
                    radius: 1,
                    red: 2,
                    green: 3,
                    blue: 4,
                },
            )
            .await
            .unwrap();

        let instance2 = ceramic
            .create_list_instance(
                &model,
                &Ball {
                    creator: ceramic.client().signer().id().id.clone(),
                    unique: "should_query_models_after_update".to_string(),
                    radius: 2,
                    red: 3,
                    green: 4,
                    blue: 5,
                },
            )
            .await
            .unwrap();

        //give anchor time to complete
        tokio::time::sleep(Duration::from_secs(1)).await;

        let replace = Ball {
            creator: ceramic.client().signer().id().id.clone(),
            unique: "should_query_models_after_update".to_string(),
            radius: 1,
            red: 0,
            green: 3,
            blue: 10,
        };
        let post_resp = ceramic.replace(&model, &instance2, &replace).await.unwrap();
        assert_eq!(post_resp.stream_id, instance2);

        //give anchor time to complete
        tokio::time::sleep(Duration::from_secs(1)).await;

        let mut where_filter = HashMap::new();
        where_filter.insert(
            "unique".to_string(),
            OperationFilter::EqualTo("should_query_models_after_update".into()),
        );
        where_filter.insert("blue".to_string(), OperationFilter::EqualTo(10.into()));
        let filter = FilterQuery::Where(where_filter);
        let res = ceramic
            .query(&model, Some(filter), Pagination::default())
            .await
            .unwrap();
        assert_eq!(res.edges.len(), 1);
        let node = &res.edges[0].node;
        let result: Ball = serde_json::from_value(node.content.clone()).unwrap();
        assert_eq!(result.blue, 10);
    }

    #[tokio::test]
    async fn should_create_and_repeatedly_update_list() {
        let ceramic = CeramicRemoteHttpClient::new(signer().await, ceramic_url());
        let model = create_model(&ceramic).await;
        let stream_id = ceramic
            .create_list_instance(
                &model,
                &Ball {
                    creator: ceramic.client().signer().id().id.clone(),
                    unique: "should_create_and_repeatedly_update_list".to_string(),
                    radius: 1,
                    red: 2,
                    green: 3,
                    blue: 4,
                },
            )
            .await
            .unwrap();

        for i in 0..100 {
            //give anchor time to complete
            tokio::time::sleep(Duration::from_millis(100)).await;

            let replace_value = rand::random::<i32>() % 10i32;
            let patch: json_patch::Patch = serde_json::from_value(serde_json::json!([
                { "op": "replace", "path": "/red", "value": replace_value },
            ]))
            .unwrap();
            let post_resp = ceramic.update(&model, &stream_id, patch).await.unwrap();
            assert_eq!(post_resp.stream_id, stream_id);
            let post_resp: Ball = serde_json::from_value(post_resp.state.unwrap().content).unwrap();
            assert_eq!(
                post_resp.red, replace_value,
                "Failed to return expected value on iteration {}",
                i
            );

            let get_resp: Ball = ceramic.get_as(&stream_id).await.unwrap();
            assert_eq!(get_resp.red, replace_value);
            assert_eq!(get_resp.blue, 4);
            assert_eq!(
                get_resp, post_resp,
                "Failed to retrieve expected value on iteration {}",
                i
            );
        }
    }
}
