# Access control design

The application uses a custom `User` identity, Argon2id password hashes, short-lived access JWTs, rotating refresh JWTs, and database-backed sessions. The access token identifies a user and session; every authenticated request also checks that the session remains active. Refresh token values are never stored, only their SHA-256 hashes.

Authorization is policy-based RBAC. Active user-role assignments connect users to active roles. Active policies connect a role, resource, and action to `none`, `own`, or `all`. The strongest matching scope wins. `own` is valid only for resources declaring ownership and requires the object owner to match the authenticated user. No role, including `admin`, bypasses policy evaluation.

```mermaid
erDiagram
    AUTH_USERS ||--o{ AUTH_SESSIONS : owns
    AUTH_USERS ||--|| USER_PROFILES : has
    AUTH_USERS ||--o{ ACCESS_USER_ROLE_ASSIGNMENTS : receives
    ACCESS_ROLES ||--o{ ACCESS_USER_ROLE_ASSIGNMENTS : assigned
    ACCESS_ROLES ||--o{ ACCESS_POLICIES : grants
    ACCESS_RESOURCES ||--o{ ACCESS_POLICIES : protects
    ACCESS_ACTIONS ||--o{ ACCESS_POLICIES : permits

    AUTH_USERS {
        uuid id PK
        string email
        string password_hash
        boolean is_active
        datetime deleted_at
    }
    AUTH_SESSIONS {
        uuid id PK
        uuid user_id FK
        string refresh_token_hash
        datetime expires_at
        datetime revoked_at
    }
    USER_PROFILES {
        uuid id PK
        uuid user_id FK
        string first_name
        string last_name
        string middle_name
    }
    ACCESS_ROLES {
        uuid id PK
        string code
        boolean is_system
        boolean is_active
    }
    ACCESS_USER_ROLE_ASSIGNMENTS {
        uuid id PK
        uuid user_id FK
        uuid role_id FK
        datetime revoked_at
    }
    ACCESS_RESOURCES {
        uuid id PK
        string code
        boolean has_owner
        boolean is_active
    }
    ACCESS_ACTIONS {
        uuid id PK
        string code
        boolean is_active
    }
    ACCESS_POLICIES {
        uuid id PK
        uuid role_id FK
        uuid resource_id FK
        uuid action_id FK
        string scope
        boolean is_active
    }
```

Authentication failures return `401` when no valid active user session can be established. Authorization failures return `403` after a user has been authenticated but no policy grants the requested action. Policy deletion is implemented as deactivation so the record remains available for audit and later reactivation.

Orders, products, and stores are process-memory demonstration objects. Their state is reset whenever the application process restarts and they have no database migrations.
