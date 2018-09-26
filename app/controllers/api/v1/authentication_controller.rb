module Api
    module V1
      class AuthenticationController < ApiApplicationController
        protect_from_forgery except: :index
        def authenticate_user
            if User.find_for_database_authentication(email: params[:email]).present?
                user = User.find_for_database_authentication(email: params[:email])
            if user.valid_password?(params[:password])
                render json: payload(user)
            else
                render json: {errors: ['Password invalido' ]}, status: :unauthorized
            end
        else
            render json: {errors: ['Isuario invalido']}, status: :unauthorized
        end
     end

     private
     
     def payload(user)
     return nil unless user and user.id
         {
             #auth_token: JsonWebToken.encode({user_id: user.id}),
             user: {id: user.id, email: user.email}
         }
     end
      end
    end
end
