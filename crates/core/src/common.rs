// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//! # Common functionality

pub mod spiffe_id;
pub use spiffe_id::{SpiffeId, SpiffePathClaims, SpiffePathMatch};

/// The first error of the independent steps of a cascade.
///
/// The steps run concurrently and every one of them runs even when another
/// failed, so the later errors would be lost. They are logged here, the first
/// one (in the order of `results`) is returned for the caller to fail with.
pub(crate) fn first_cascade_error<E: std::fmt::Display>(
    results: impl IntoIterator<Item = Result<(), E>>,
) -> Result<(), E> {
    let mut first = None;
    for result in results {
        if let Err(err) = result {
            if first.is_none() {
                first = Some(err);
            } else {
                tracing::error!(error = %err, "a cascade step failed after an earlier error");
            }
        }
    }
    first.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::first_cascade_error;

    #[test]
    fn first_cascade_error_returns_the_first() {
        assert_eq!(first_cascade_error::<String>([Ok(()), Ok(())]), Ok(()));
        assert_eq!(
            first_cascade_error([Ok(()), Err("a".to_string()), Err("b".to_string())]),
            Err("a".to_string())
        );
    }
}
