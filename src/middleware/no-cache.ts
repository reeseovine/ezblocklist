import { Request, Response, NextFunction } from 'express'

export default function noCache() {
	return (_: Request, response: Response, next: NextFunction): void => {
		response.setHeader('Surrogate-Control', 'no-store')
		response.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate')
		response.setHeader('Pragma', 'no-cache')
		response.setHeader('Expires', '0')

		next()
	}
}
