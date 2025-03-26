# API Key Rotation Strategy

## Why Rotate API Keys?

- **Security best practice**: Regular rotation reduces the risk if a key is compromised
- **Compliance requirements**: Many security frameworks require periodic credential rotation
- **Access control**: Remove access for departed team members or deprecated services

## Rotation Strategy

### 1. Preparation Phase

1. **Determine rotation schedule**:
   - Set a regular schedule (e.g., quarterly)
   - Document the process in your security procedures

2. **Identify dependencies**:
   - Map all services and applications using the current API key
   - Ensure you have access to update configurations in all locations

### 2. Implementation Phase

1. **Generate a new API key**:
   ```bash
   python nylas_api_key_generator.py create --name "production-key-YYYY-MM-DD" --expires 7776000
   ```
   - Use a descriptive name with date for tracking
   - Set an appropriate expiration (e.g., 90 days = 7776000 seconds)

2. **Implement parallel operation**:
   - Deploy the new key to your applications but keep the old one active
   - Configure your application to try the new key first, falling back to the old key if needed
   - Monitor for any issues with the new key

3. **Gradual transition**:
   - Update services one by one to use the new key exclusively
   - Maintain a rollback plan in case of unexpected issues

### 3. Verification Phase

1. **Confirm all services are using the new key**:
   - Monitor API usage patterns to verify the new key is being used
   - Check logs for any fallbacks to the old key

2. **Decommission the old key**:
   ```bash
   python nylas_api_key_generator.py delete <old_api_key_id>
   ```

3. **Verify application functionality**:
   - Run integration tests to ensure everything works with only the new key
   - Monitor for any unexpected errors

## Automation Recommendations

1. **Create a rotation script**:
   - Automate the creation of new keys
   - Update configuration files or secrets management systems
   - Implement automatic verification tests

2. **Integrate with CI/CD**:
   - Trigger key rotation as part of your deployment pipeline
   - Include verification steps before completing the rotation

3. **Monitoring and alerts**:
   - Set up alerts for key expiration dates
   - Monitor for authentication failures that might indicate rotation issues

## Emergency Rotation

In case of a suspected security breach:

1. **Immediate revocation**:
   ```bash
   python nylas_api_key_generator.py delete <compromised_key_id>
   ```

2. **Generate a new key**:
   ```bash
   python nylas_api_key_generator.py create --name "emergency-key-YYYY-MM-DD" --expires 7776000
   ```

3. **Emergency deployment**:
   - Update all services with the new key as quickly as possible
   - Consider temporary service disruption if necessary for security