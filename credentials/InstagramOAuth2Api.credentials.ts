import type {
	ICredentialDataDecryptedObject,
	ICredentialTestRequest,
	ICredentialType,
	IDataObject,
	IHttpRequestHelper,
	INodeProperties,
} from 'n8n-workflow';

export class InstagramOAuth2Api implements ICredentialType {
	name = 'instagramOAuth2Api';
	extends = ['oAuth2Api'];
	displayName = 'Instagram OAuth2 API';
	documentationUrl = 'https://developers.facebook.com/docs/instagram-api/getting-started';
	properties: INodeProperties[] = [
		{
			displayName: 'Grant Type',
			name: 'grantType',
			type: 'hidden',
			default: 'authorizationCode',
		},
		// CORREÇÃO 1: URLs apontando para o Facebook (Meta), pois é conta Business
		{
			displayName: 'Authorization URL',
			name: 'authUrl',
			type: 'hidden',
			default: 'https://www.facebook.com/v20.0/dialog/oauth',
		},
		{
			displayName: 'Access Token URL',
			name: 'accessTokenUrl',
			type: 'hidden',
			default: 'https://graph.facebook.com/v20.0/oauth/access_token',
		},
		{
			displayName: 'Scope',
			name: 'scope',
			type: 'hidden',
			// Escopos atualizados para garantir acesso total ao Business
			default: 'instagram_basic,instagram_content_publish,pages_show_list,pages_read_engagement,business_management',
		},
		{
			displayName: 'Auth URI Query Parameters',
			name: 'authQueryParameters',
			type: 'hidden',
			default: '',
		},
		{
			displayName: 'Authentication',
			name: 'authentication',
			type: 'hidden',
			default: 'body',
		},
		{
			displayName: 'Account Information',
			name: 'accountInfoNotice',
			type: 'notice',
			default: '',
			description: 'After connecting, n8n will automatically exchange your token for a Long-Lived Token (60 days). Note: For Business accounts, you must re-authenticate manually every 60 days as per Meta security policies.',
		},
		{
			displayName: 'Client ID',
			name: 'clientId',
			type: 'string',
			default: '',
			required: true,
			description: 'The App ID from your Meta Developer Console',
		},
		{
			displayName: 'Client Secret',
			name: 'clientSecret',
			type: 'string',
			typeOptions: {
				password: true,
			},
			default: '',
			required: true,
			description: 'The App Secret from your Meta Developer Console',
		},
		// Propriedade para guardar o token de longa duração
		{
			displayName: 'Long-Lived Token',
			name: 'longLivedToken',
			type: 'hidden',
			typeOptions: {
				expirable: true, // Importante para o n8n saber que pode mudar
			},
			default: '',
		},
		{
			displayName: 'Token Expires At',
			name: 'tokenExpiresAt',
			type: 'hidden',
			default: 0,
		},
	];

	// CORREÇÃO 2: Lógica de troca correta para fb_exchange_token
	async preAuthentication(
		this: IHttpRequestHelper,
		credentials: ICredentialDataDecryptedObject,
	): Promise<IDataObject> {
		const now = Math.floor(Date.now() / 1000);
		const longLivedToken = credentials.longLivedToken as string;
		const tokenExpiresAt = (credentials.tokenExpiresAt as number) || 0;
		const clientSecret = credentials.clientSecret as string;
		const clientId = credentials.clientId as string;
		const oauthTokenData = credentials.oauthTokenData as { access_token?: string } | undefined;
		const shortLivedToken = oauthTokenData?.access_token;

		// 1. Se já temos um token válido e longe de expirar (mais de 3 dias), não faz nada.
		if (longLivedToken && tokenExpiresAt > now + (3 * 24 * 60 * 60)) {
			return {};
		}

		// 2. Se não temos token curto para trocar, aborta.
		if (!shortLivedToken) {
			return {};
		}

		// 3. Tenta trocar o Token Curto (ou o próprio Longo antigo) por um NOVO Token Longo
		// Usamos a API do Facebook (graph.facebook.com) e não do Instagram
		try {
			// Nota: Para "refresh" no Facebook, você basicamente troca o token antigo por um novo
			// usando o mesmo endpoint de exchange.
			const tokenToExchange = longLivedToken || shortLivedToken;

			const response = await this.helpers.httpRequest({
				method: 'GET',
				url: 'https://graph.facebook.com/v20.0/oauth/access_token',
				qs: {
					grant_type: 'fb_exchange_token', // A mágica acontece aqui
					client_id: clientId,
					client_secret: clientSecret,
					fb_exchange_token: tokenToExchange,
				},
			}) as { access_token: string; expires_in: number };

			if (response.access_token) {
				return {
					longLivedToken: response.access_token,
					// Meta retorna expires_in em segundos (geralmente 60 dias / ~5184000)
					tokenExpiresAt: now + response.expires_in,
				};
			}
		} catch (error) {
			console.error('Instagram Business: Failed to exchange token', error);
			// Se falhar, não retornamos erro para não quebrar o fluxo imediatamente,
			// deixamos tentar usar o token que já existe (se houver).
			return {};
		}

		return {};
	}

	test: ICredentialTestRequest = {
		request: {
			// CORREÇÃO 3: Endpoint de teste no Graph do Facebook
			baseURL: 'https://graph.facebook.com/v20.0',
			url: '/me',
			method: 'GET',
			qs: {
				fields: 'id,name',
			},
		},
	};
}
