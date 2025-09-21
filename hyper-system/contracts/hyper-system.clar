;; HyperSystem - Decentralized Identity and Reputation Infrastructure
;; A simplified implementation focusing on core functionality

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-insufficient-stake (err u103))
(define-constant err-invalid-attestation (err u104))
(define-constant err-unauthorized (err u105))

;; Minimum stake required for validators (in microSTX)
(define-constant min-validator-stake u1000000) ;; 1 STX

;; Reputation decay rate (blocks)
(define-constant reputation-decay-period u2016) ;; ~2 weeks

;; Data Variables
(define-data-var next-identity-id uint u1)
(define-data-var attestation-counter uint u0)

;; Data Maps

;; Identity Anchors - Core immutable identifiers
(define-map identity-anchors
  { identity-id: uint }
  {
    owner: principal,
    public-key-hash: (buff 32),
    created-at: uint,
    is-active: bool
  }
)

;; Principal to Identity mapping
(define-map principal-to-identity
  { owner: principal }
  { identity-id: uint }
)

;; Reputation Vectors - Multi-dimensional trust metrics
(define-map reputation-scores
  { identity-id: uint, category: (string-ascii 32) }
  {
    score: uint,
    last-updated: uint,
    attestation-count: uint
  }
)

;; Validator Registry
(define-map validators
  { validator: principal }
  {
    stake-amount: uint,
    reputation: uint,
    active: bool,
    joined-at: uint
  }
)

;; Attestations
(define-map attestations
  { attestation-id: uint }
  {
    validator: principal,
    target-identity: uint,
    category: (string-ascii 32),
    score-delta: int,
    timestamp: uint,
    stake-amount: uint
  }
)

;; Attestation tracking for slashing
(define-map validator-attestations
  { validator: principal, attestation-id: uint }
  { is-valid: bool, challenged: bool }
)

;; Read-only functions

;; Get identity information
(define-read-only (get-identity (identity-id uint))
  (map-get? identity-anchors { identity-id: identity-id })
)

;; Get identity by principal
(define-read-only (get-identity-by-principal (owner principal))
  (match (map-get? principal-to-identity { owner: owner })
    identity-record (some { 
      identity-id: (get identity-id identity-record),
      identity-data: (get-identity (get identity-id identity-record))
    })
    none
  )
)

;; Get reputation score for a specific category
(define-read-only (get-reputation-score (identity-id uint) (category (string-ascii 32)))
  (match (map-get? reputation-scores { identity-id: identity-id, category: category })
    score-record 
    (let ((blocks-elapsed (- block-height (get last-updated score-record))))
      (if (> blocks-elapsed reputation-decay-period)
        ;; Apply decay if too much time has passed
        (some { 
          score: (/ (get score score-record) u2), 
          last-updated: (get last-updated score-record),
          attestation-count: (get attestation-count score-record)
        })
        (some score-record)
      )
    )
    none
  )
)

;; Get validator information
(define-read-only (get-validator (validator principal))
  (map-get? validators { validator: validator })
)

;; Get attestation details
(define-read-only (get-attestation (attestation-id uint))
  (map-get? attestations { attestation-id: attestation-id })
)

;; Check if principal has sufficient reputation in category
(define-read-only (has-reputation-threshold (owner principal) (category (string-ascii 32)) (threshold uint))
  (match (get-identity-by-principal owner)
    identity-record
    (match (get-reputation-score (get identity-id identity-record) category)
      reputation-record (>= (get score reputation-record) threshold)
      false
    )
    false
  )
)

;; Public functions

;; Create a new identity anchor
(define-public (create-identity (public-key-hash (buff 32)))
  (let ((identity-id (var-get next-identity-id)))
    (asserts! (is-none (get-identity-by-principal tx-sender)) err-already-exists)
    (map-set identity-anchors
      { identity-id: identity-id }
      {
        owner: tx-sender,
        public-key-hash: public-key-hash,
        created-at: block-height,
        is-active: true
      }
    )
    (map-set principal-to-identity
      { owner: tx-sender }
      { identity-id: identity-id }
    )
    (var-set next-identity-id (+ identity-id u1))
    (ok identity-id)
  )
)

;; Register as a validator by staking STX
(define-public (register-validator (stake-amount uint))
  (begin
    (asserts! (>= stake-amount min-validator-stake) err-insufficient-stake)
    (asserts! (is-none (get-validator tx-sender)) err-already-exists)
    
    ;; Transfer stake to contract
    (try! (stx-transfer? stake-amount tx-sender (as-contract tx-sender)))
    
    (map-set validators
      { validator: tx-sender }
      {
        stake-amount: stake-amount,
        reputation: u100, ;; Start with base reputation
        active: true,
        joined-at: block-height
      }
    )
    (ok true)
  )
)

;; Submit an attestation about an identity's reputation
(define-public (submit-attestation 
  (target-identity uint) 
  (category (string-ascii 32)) 
  (score-delta int)
  (attestation-stake uint))
  (let (
    (attestation-id (var-get attestation-counter))
    (validator-info (unwrap! (get-validator tx-sender) err-unauthorized))
  )
    (asserts! (get active validator-info) err-unauthorized)
    (asserts! (is-some (get-identity target-identity)) err-not-found)
    (asserts! (<= attestation-stake (get stake-amount validator-info)) err-insufficient-stake)
    
    ;; Store the attestation
    (map-set attestations
      { attestation-id: attestation-id }
      {
        validator: tx-sender,
        target-identity: target-identity,
        category: category,
        score-delta: score-delta,
        timestamp: block-height,
        stake-amount: attestation-stake
      }
    )
    
    ;; Track for potential slashing
    (map-set validator-attestations
      { validator: tx-sender, attestation-id: attestation-id }
      { is-valid: true, challenged: false }
    )
    
    ;; Update reputation score
    (match (get-reputation-score target-identity category)
      existing-score
      (map-set reputation-scores
        { identity-id: target-identity, category: category }
        {
          score: (if (> score-delta 0) 
                   (+ (get score existing-score) (to-uint score-delta))
                   (if (> (get score existing-score) (to-uint (* score-delta -1)))
                     (- (get score existing-score) (to-uint (* score-delta -1)))
                     u0)),
          last-updated: block-height,
          attestation-count: (+ (get attestation-count existing-score) u1)
        }
      )
      ;; First attestation for this category
      (map-set reputation-scores
        { identity-id: target-identity, category: category }
        {
          score: (if (> score-delta 0) (to-uint score-delta) u0),
          last-updated: block-height,
          attestation-count: u1
        }
      )
    )
    
    (var-set attestation-counter (+ attestation-id u1))
    (ok attestation-id)
  )
)

;; Challenge an attestation (simplified slashing mechanism)
(define-public (challenge-attestation (attestation-id uint))
  (let (
    (attestation (unwrap! (get-attestation attestation-id) err-not-found))
    (challenger-validator (unwrap! (get-validator tx-sender) err-unauthorized))
  )
    (asserts! (get active challenger-validator) err-unauthorized)
    (asserts! (not (is-eq tx-sender (get validator attestation))) err-invalid-attestation)
    
    ;; Mark as challenged (in a real implementation, this would trigger dispute resolution)
    (map-set validator-attestations
      { validator: (get validator attestation), attestation-id: attestation-id }
      { is-valid: false, challenged: true }
    )
    
    (ok true)
  )
)

;; Deactivate identity (emergency function)
(define-public (deactivate-identity (identity-id uint))
  (let ((identity (unwrap! (get-identity identity-id) err-not-found)))
    (asserts! (or (is-eq tx-sender (get owner identity)) (is-eq tx-sender contract-owner)) err-unauthorized)
    (map-set identity-anchors
      { identity-id: identity-id }
      (merge identity { is-active: false })
    )
    (ok true)
  )
)

;; Withdraw validator stake (after cooldown period)
(define-public (withdraw-validator-stake)
  (let ((validator-info (unwrap! (get-validator tx-sender) err-not-found)))
    (asserts! (not (get active validator-info)) err-invalid-attestation)
    ;; In production, add cooldown period check
    (try! (as-contract (stx-transfer? (get stake-amount validator-info) tx-sender tx-sender)))
    (map-delete validators { validator: tx-sender })
    (ok (get stake-amount validator-info))
  )
)

;; Deactivate validator
(define-public (deactivate-validator)
  (match (get-validator tx-sender)
    validator-info
    (begin
      (map-set validators
        { validator: tx-sender }
        (merge validator-info { active: false })
      )
      (ok true)
    )
    err-not-found
  )
)