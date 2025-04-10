import { HttpEvent, HttpHandlerFn, HttpRequest } from '@angular/common/http';
import { inject, EventEmitter, Output } from '@angular/core';
import { Router } from '@angular/router';
import { ToastrService } from 'ngx-toastr';
import { Observable, catchError, switchMap, throwError } from 'rxjs';
import { AppComponent } from '../app.component';
import { AuthService } from './auth.service';

export function jwtInterceptor(req: HttpRequest<unknown>, next: HttpHandlerFn): Observable<HttpEvent<unknown>> {
  
  console.log("Dentro del interceptador");

  const apiService = inject(AuthService);

  const token = localStorage.getItem('access_token');
  const router = inject(Router);
  const toastr = inject(ToastrService);

  if (token) {
    req = req.clone({
      setHeaders: {
        Authorization: `Bearer ${token}`
      }
    });
  }


  return next(req).pipe(
    catchError((error) => {
      if (error.status === 401 || error.status === 403 || error.status === 500) {
        const refreshToken = localStorage.getItem('refresh_token');
        if (refreshToken) {
          return apiService.refreshToken(refreshToken).pipe(
            switchMap((response) => {
              console.log(response);
              if (response)
              {
              localStorage.setItem('access_token', response.accessToken); // Actualitza el token
              console.log('Token actualitzat:', response.accessToken);
              const access_token = response.accessToken;
              if(access_token)
              {
                req = req.clone({
                  setHeaders: {
                    Authorization: `Bearer ${access_token}`
                  }
                });

              }
              return next(req);
            }
            else{
              throw new Error('No se recibió un nuevo');
            }
              // Reintenta la petició amb el nou token
            }),
            catchError(() => {
              localStorage.removeItem('access_token'); // Neteja token si no és vàlid
              localStorage.removeItem('refresh_token'); // Neteja refresh token si no és vàlid
              toastr.error(
                'Su sesión ha expirado. Por favor, inicie sesión nuevamente.',
                'Sesión Expirada',
                {
                  timeOut: 3000,
                  closeButton: true
                }
              );
              router.navigate(['/login']); // Redirigeix a la pàgina de login
              return throwError(() => error);
            })
          );
        }
        localStorage.removeItem('access_token'); // Neteja token si no és vàlid
        toastr.error(
          'Su sesión ha expirado. Por favor, inicie sesión nuevamente.',
          'Sesión Expirada',
          {
            timeOut: 3000,
            closeButton: true
          }
        );
      }
      return throwError(() => error);
    })
  );
}
