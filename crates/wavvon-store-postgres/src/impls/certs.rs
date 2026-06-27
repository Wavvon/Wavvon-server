use async_trait::async_trait;
use sqlx::Row;
use wavvon_store::{
    CertIssuanceRow, CertStore, PairingOfferRow, PrefsBlobRow, StoreError, UserCertRow,
};

use crate::error_map::map_err;
use crate::PostgresStore;

fn row_to_cert_issuance(r: sqlx::postgres::PgRow) -> CertIssuanceRow {
    CertIssuanceRow {
        id: r.get("id"),
        subject_pubkey: r.get("subject_pubkey"),
        pow_level: r.get("pow_level"),
        member_since: r.get("member_since"),
        issued_at: r.get("issued_at"),
        expires_at: r.get("expires_at"),
        revoked_at: r.get("revoked_at"),
        standing: r.get("standing"),
        payload_json: r.get("payload_json"),
        signature: r.get("signature"),
    }
}

#[async_trait]
impl CertStore for PostgresStore {
    async fn insert_cert_issuance(&self, c: &CertIssuanceRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO cert_issuances
             (id, subject_pubkey, pow_level, member_since, issued_at, expires_at,
              revoked_at, standing, payload_json, signature)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(&c.id)
        .bind(&c.subject_pubkey)
        .bind(c.pow_level)
        .bind(c.member_since)
        .bind(c.issued_at)
        .bind(c.expires_at)
        .bind(c.revoked_at)
        .bind(&c.standing)
        .bind(&c.payload_json)
        .bind(&c.signature)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn latest_cert_for_subject(
        &self,
        subject_pubkey: &str,
    ) -> Result<Option<CertIssuanceRow>, StoreError> {
        let row = sqlx::query(
            "SELECT id, subject_pubkey, pow_level, member_since, issued_at, expires_at,
                    revoked_at, standing, payload_json, signature
             FROM cert_issuances
             WHERE subject_pubkey = $1
             ORDER BY issued_at DESC LIMIT 1",
        )
        .bind(subject_pubkey)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(row_to_cert_issuance))
    }

    async fn list_certs_for_subject(
        &self,
        subject_pubkey: &str,
    ) -> Result<Vec<CertIssuanceRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, subject_pubkey, pow_level, member_since, issued_at, expires_at,
                    revoked_at, standing, payload_json, signature
             FROM cert_issuances
             WHERE subject_pubkey = $1
             ORDER BY issued_at DESC",
        )
        .bind(subject_pubkey)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows.into_iter().map(row_to_cert_issuance).collect())
    }

    async fn revoke_cert(&self, id: &str, revoked_at: i64) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE cert_issuances SET revoked_at = $1, standing = 'revoked' WHERE id = $2",
        )
        .bind(revoked_at)
        .bind(id)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn insert_user_cert(&self, c: &UserCertRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO user_certs
             (id, master_pubkey, issuer_pubkey, issuer_url, payload_json, signature, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(&c.id)
        .bind(&c.master_pubkey)
        .bind(&c.issuer_pubkey)
        .bind(&c.issuer_url)
        .bind(&c.payload_json)
        .bind(&c.signature)
        .bind(c.expires_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn list_user_certs(&self, master_pubkey: &str) -> Result<Vec<UserCertRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT id, master_pubkey, issuer_pubkey, issuer_url, payload_json, signature, expires_at
             FROM user_certs WHERE master_pubkey = $1",
        )
        .bind(master_pubkey)
        .fetch_all(self.pool())
        .await
        .map_err(map_err)?;
        Ok(rows
            .into_iter()
            .map(|r| UserCertRow {
                id: r.get("id"),
                master_pubkey: r.get("master_pubkey"),
                issuer_pubkey: r.get("issuer_pubkey"),
                issuer_url: r.get("issuer_url"),
                payload_json: r.get("payload_json"),
                signature: r.get("signature"),
                expires_at: r.get("expires_at"),
            })
            .collect())
    }

    async fn delete_expired_user_certs(&self, now: i64) -> Result<u64, StoreError> {
        let result = sqlx::query("DELETE FROM user_certs WHERE expires_at < $1")
            .bind(now)
            .execute(self.pool())
            .await
            .map_err(map_err)?;
        Ok(result.rows_affected())
    }

    async fn upsert_pairing_offer(&self, p: &PairingOfferRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO pairing_offers
             (pairing_token, master_pubkey, home_hubs_json, issued_at, expires_at,
              offer_signature, state, subkey_pubkey, device_label, claim_proof,
              cert_json, wrapped_key_hex, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
             ON CONFLICT(pairing_token) DO UPDATE SET
               state = excluded.state,
               subkey_pubkey = excluded.subkey_pubkey,
               device_label = excluded.device_label,
               claim_proof = excluded.claim_proof,
               cert_json = excluded.cert_json,
               wrapped_key_hex = excluded.wrapped_key_hex,
               updated_at = excluded.updated_at",
        )
        .bind(&p.pairing_token)
        .bind(&p.master_pubkey)
        .bind(&p.home_hubs_json)
        .bind(p.issued_at)
        .bind(p.expires_at)
        .bind(&p.offer_signature)
        .bind(&p.state)
        .bind(&p.subkey_pubkey)
        .bind(&p.device_label)
        .bind(&p.claim_proof)
        .bind(&p.cert_json)
        .bind(&p.wrapped_key_hex)
        .bind(p.created_at)
        .bind(p.updated_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_pairing_offer(&self, token: &str) -> Result<Option<PairingOfferRow>, StoreError> {
        let row = sqlx::query(
            "SELECT pairing_token, master_pubkey, home_hubs_json, issued_at, expires_at,
                    offer_signature, state, subkey_pubkey, device_label, claim_proof,
                    cert_json, wrapped_key_hex, created_at, updated_at
             FROM pairing_offers WHERE pairing_token = $1",
        )
        .bind(token)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(|r| PairingOfferRow {
            pairing_token: r.get("pairing_token"),
            master_pubkey: r.get("master_pubkey"),
            home_hubs_json: r.get("home_hubs_json"),
            issued_at: r.get("issued_at"),
            expires_at: r.get("expires_at"),
            offer_signature: r.get("offer_signature"),
            state: r.get("state"),
            subkey_pubkey: r.get("subkey_pubkey"),
            device_label: r.get("device_label"),
            claim_proof: r.get("claim_proof"),
            cert_json: r.get("cert_json"),
            wrapped_key_hex: r.get("wrapped_key_hex"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    async fn update_pairing_offer_state(
        &self,
        token: &str,
        state: &str,
        updated_at: i64,
        subkey_pubkey: Option<&str>,
        device_label: Option<&str>,
        claim_proof: Option<&str>,
        cert_json: Option<&str>,
        wrapped_key_hex: Option<&str>,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "UPDATE pairing_offers SET
               state = $1, updated_at = $2,
               subkey_pubkey = COALESCE($3, subkey_pubkey),
               device_label = COALESCE($4, device_label),
               claim_proof = COALESCE($5, claim_proof),
               cert_json = COALESCE($6, cert_json),
               wrapped_key_hex = COALESCE($7, wrapped_key_hex)
             WHERE pairing_token = $8",
        )
        .bind(state)
        .bind(updated_at)
        .bind(subkey_pubkey)
        .bind(device_label)
        .bind(claim_proof)
        .bind(cert_json)
        .bind(wrapped_key_hex)
        .bind(token)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn upsert_prefs_blob(&self, p: &PrefsBlobRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO prefs_blobs
             (master_pubkey, blob_version, ciphertext_hex, signature, updated_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT(master_pubkey) DO UPDATE SET
               blob_version = excluded.blob_version,
               ciphertext_hex = excluded.ciphertext_hex,
               signature = excluded.signature,
               updated_at = excluded.updated_at",
        )
        .bind(&p.master_pubkey)
        .bind(p.blob_version)
        .bind(&p.ciphertext_hex)
        .bind(&p.signature)
        .bind(p.updated_at)
        .execute(self.pool())
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn get_prefs_blob(
        &self,
        master_pubkey: &str,
    ) -> Result<Option<PrefsBlobRow>, StoreError> {
        let row = sqlx::query(
            "SELECT master_pubkey, blob_version, ciphertext_hex, signature, updated_at
             FROM prefs_blobs WHERE master_pubkey = $1",
        )
        .bind(master_pubkey)
        .fetch_optional(self.pool())
        .await
        .map_err(map_err)?;
        Ok(row.map(|r| PrefsBlobRow {
            master_pubkey: r.get("master_pubkey"),
            blob_version: r.get("blob_version"),
            ciphertext_hex: r.get("ciphertext_hex"),
            signature: r.get("signature"),
            updated_at: r.get("updated_at"),
        }))
    }
}
