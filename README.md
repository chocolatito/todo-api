# RESTful JSON API With Rails 6 - Ver. 2

Example based on the tutorial:
> [___Build a RESTful JSON API With Rails 5 - Part Two___](https://www.digitalocean.com/community/tutorials/build-a-restful-json-api-with-rails-5-part-two)

Continuation of branch
> [***`parte_1`***](https://github.com/chocolatito/todo-api/tree/parte_1)


#### Using
  - `Ruby 2.5.5`
  - `Rails 6.1.4.1`

#### Sumary
+ [Requirements](#requirements)
    - [Data](#data)
    - [API Endpoints](#api-endpoints)
+ [Project Setup](#project-setup)
    - [Dependencies](#dependencies)
    - [Prepare Test Environment](#prepare-test-environment)
+ [User Authentication](#user-authentication)
    - [Genete Model](#generate-model)
    - [Model specs](#)
+ [Token web JSON](#token-web-json)
    - [JsonWebToken class and ExceptionHandler module](#jsonwebtoken-class-and-exceptionhandler-module)
    - [Authorize API Request](#authorize-api-request)
+ [Authenticate Users](#authenticate-users)
+ [Authentication Controller](#authentication-controller)
    - [User controller](#user-controller)
+ [Continues In](#continues-in)

---
## Requirements

### Data
- **Todo** : *(title:string, created_by:string)*
- **Item** : *(name:string, done:boolean)*
- **User** : *(name:string, email:string, password_digest:string)*

A **Todo**, has zero or many **Item** records

An **Item**, has only one **Item**

An **User**, has zero or many **Todo** records

A **Todo**, has one **User** records

### API Endpoints

Does not require
- __Log in__
- __Authorization through Json Web Token__

|**Verb**|**URI_Pattern**|**Controller#Actio**|
|------------|------------|------------|
|`POST` | */signup* | __users#create__ |
|`POST` | */auth/login* | __authentication#authenticate__ |

Require __Log in__ and __Authorization through Json Web Token__

|**Verb**|**URI_Pattern**|**Controller#Actio**|
|------------|------------|------------|
|`GET` |_/todos_  | __todos#index__ |
|`POST` |_/todos_ | __todos#create__|
|`GET` |_/todos/:id_ | __todos#show__|
|`PUT` |_/todos/:id_ | __todos#update__ | 
|`DELETE` |_/todos/:id_ | __todos#destroy__ |
|`GET` |*/todos/:todo_id/items* | __items#index__ |
|`POST` | */todos/:todo_id/items* | __items#create__ |
|`GET` |*/todos/:todo_id/items/:id* | __items#show__ |
|`PUT` |*/todos/:todo_id/items/:id* |  __items#update__ |
|`DELETE` |*/todos/:todo_id/items/:id* |  __items#destroy__ |


---
## Project Setup

>___./Gemfile___
```ruby
# [...]
# Use Active Model has_secure_password
gem 'bcrypt', '~> 3.1.7'
# [...]
# Implement token-based authentication.
gem 'jwt'
# [...]
```

Install the gem.
```sh
bundle install
```

---
### Prepare Test Environment

Include `RequestSpecHelper` to all types (not just requests such ass part one) for be able to reuse a handy json helper.
>***./rails_helper***
```ruby
RSpec.configure do |config|
  # [...]
  # previously `config.include RequestSpecHelper, type: :request`
  config.include RequestSpecHelper
  config.include ControllerSpecHelper
  # [...]
end
```

---
## User Authentication

### Genete Model

`User` model
```sh
rails g model User name:string email:string password_digest:string
```

Run the migrations.
```sh
rails db:migrate
```

make sure the test environment is ready
```sh
rails db:test:prepare
```

### Model specs
> ***./spec/models/user_spec.rb***
```ruby
require 'rails_helper'

# Test suite for User model
RSpec.describe User, type: :model do
  # Association test
  # ensure User model has a 1:m relationship with the Todo model
  it { should have_many(:todos) }
  # Validation tests
  # ensure name, email and password_digest are present before save
  it { should validate_presence_of(:name) }
  it { should validate_presence_of(:email) }
  it { should validate_presence_of(:password_digest) }
end
```

Add a user factory
```sh
touch spec/factories/users.rb
```

>***./spec/factories/users.rb***
```ruby
FactoryBot.define do
  factory :user do
    name { Faker::Name.name }
    email 'foo@bar.com'
    password 'foobar'
  end
end
```

>***./app/models/user.rb***
```ruby
class User < ApplicationRecord
  # encrypt password
  has_secure_password

  # Model associations
  has_many :todos, foreign_key: :created_by
  # Validations
  validates_presence_of :name, :email, :password_digest
end
```

Execute the specs:  
```sh
bundle exec rspec
```
only models specs
```sh
bundle exec rspec spec/models/
```

---
## Token web JSON
JsonWebToken class will live in the `lib` directory since it’s not domain specific
___if we were to move it to a different application it should work with minimal configuration___ 

> As of Rails 5, autoloading is disabled in production because of thread safety.

Since `lib` is part of auto-load paths, it should be added to in `app` directory, since all code in-app is auto-loaded in development and eager-loaded in production.
All code in-app is auto-loaded in development and eager-loaded in production.

### _JsonWebToken_ class and _ExceptionHandler_ module 

create custom lib
```sh
mkdir app/lib && \
touch app/lib/json_web_token.rb
```

Define jwt [singleton](https://en.wikipedia.org/wiki/Singleton_pattern)
>***./app/lib/json_web_token.rb***
```ruby
class JsonWebToken
  # secret to encode and decode token
  HMAC_SECRET = Rails.application.secrets.secret_key_base

  def self.encode(payload, exp = 24.hours.from_now)
    # set expiry to 24 hours from creation time
    payload[:exp] = exp.to_i
    # sign token with application secret
    JWT.encode(payload, HMAC_SECRET)
  end

  def self.decode(token)
    # get payload; first index in decoded Array
    body = JWT.decode(token, HMAC_SECRET)[0]
    HashWithIndifferentAccess.new body
    # rescue from all decode errors
  rescue JWT::DecodeError => e
    # raise custom error to be handled by custom handler
    raise ExceptionHandler::InvalidToken, e.message
  end
end
```

This singleton wraps `JWT` to provide token encoding and decoding methods.
- The `encoding` method: Will be responsible for creating tokens based on a payload (user id) and expiration period. It use Rails project secret key that as secret to sign tokens.
- The `decode` method: Accepts a token and attempts to decode it using the same secret used in the encoding. In the event decoding fails, be it due to expiration or validation, JWT will raise respective exceptions which will be caught and handled by the `ExceptionHandler` module.

### Authorize API Request
This class will be responsible for authorizing all API requests making sure that all requests have a valid token and user payload.

Since this is an authentication service class, it’ll live in `app/auth`.

Create _auth_ folder to house auth services
```sh
mkdir app/auth && \
touch app/auth/authorize_api_request.rb && \
touch app/auth/exception_handler.rb
```

Create corresponding spec files
```sh
mkdir spec/auth && \
touch spec/auth/authorize_api_request_spec.rb
```

Define it's specifications
>***./spec/auth/authorize_api_request_spec.rb***
```ruby
require 'rails_helper'

RSpec.describe AuthorizeApiRequest do
  # Create test user
  let(:user) { create(:user) }
  # Mock `Authorization` header
  let(:header) { { 'Authorization' => token_generator(user.id) } }
  # Invalid request subject
  subject(:invalid_request_obj) { described_class.new({}) }
  # Valid request subject
  subject(:request_obj) { described_class.new(header) }

  # Test Suite for AuthorizeApiRequest#call
  # This is our entry point into the service class
  describe '#call' do
    # returns user object when request is valid
    context 'when valid request' do
      it 'returns user object' do
        result = request_obj.call
        expect(result[:user]).to eq(user)
      end
    end

    # returns error message when invalid request
    context 'when invalid request' do
      context 'when missing token' do
        it 'raises a MissingToken error' do
          expect { invalid_request_obj.call }
            .to raise_error(ExceptionHandler::MissingToken, 'Missing token')
        end
      end

      context 'when invalid token' do
        subject(:invalid_request_obj) do
          # custom helper method `token_generator`
          described_class.new('Authorization' => token_generator(5))
        end

        it 'raises an InvalidToken error' do
          expect { invalid_request_obj.call }
            .to raise_error(ExceptionHandler::InvalidToken, /Invalid token/)
        end
      end

      context 'when token is expired' do
        let(:header) { { 'Authorization' => expired_token_generator(user.id) } }
        subject(:request_obj) { described_class.new(header) }

        it 'raises ExceptionHandler::ExpiredSignature error' do
          expect { request_obj.call }
            .to raise_error(
              ExceptionHandler::InvalidToken,
              /Signature has expired/
            )
        end
      end

      context 'fake token' do
        let(:header) { { 'Authorization' => 'foobar' } }
        subject(:invalid_request_obj) { described_class.new(header) }

        it 'handles JWT::DecodeError' do
          expect { invalid_request_obj.call }
            .to raise_error(
              ExceptionHandler::InvalidToken,
              /Not enough or too many segments/
            )
        end
      end
    end
  end
end
```

The AuthorizeApiRequest service should have an entry method call that returns a valid user object when the request is valid and raises an error when invalid.

Test helper methods
- `token_generator` - generate test token
- `expired_token_generator` - generate expired token

Create module file
```sh
touch spec/support/controller_spec_helper.rb
```

>***./spec/support/controller_spec_helper.rb***
```ruby
module ControllerSpecHelper
  # generate tokens from user id
  def token_generator(user_id)
    JsonWebToken.encode(user_id: user_id)
  end

  # generate expired tokens from user id
  def expired_token_generator(user_id)
    JsonWebToken.encode({ user_id: user_id }, (Time.now.to_i - 10))
  end

  # return valid headers
  def valid_headers
    {
      "Authorization" => token_generator(user.id),
      "Content-Type" => "application/json"
    }
  end

  # return invalid headers
  def invalid_headers
    {
      "Authorization" => nil,
      "Content-Type" => "application/json"
    }
  end
end
```

Define the `AuthorizeApiRequest` service
>***./app/auth/authorize_api_request.rb***
```ruby
class AuthorizeApiRequest
  def initialize(headers = {})
    @headers = headers
  end

  # Service entry point - return valid user object
  def call
    {
      user: user
    }
  end

  private

  attr_reader :headers

  def user
    # check if user is in the database
    # memoize user object
    @user ||= User.find(decoded_auth_token[:user_id]) if decoded_auth_token
    # handle user not found
  rescue ActiveRecord::RecordNotFound => e
    # raise custom error
    raise(
      ExceptionHandler::InvalidToken,
      ("#{Message.invalid_token} #{e.message}")
    )
  end

  # decode authentication token
  def decoded_auth_token
    @decoded_auth_token ||= JsonWebToken.decode(http_auth_header)
  end

  # check for token in `Authorization` header
  def http_auth_header
    if headers['Authorization'].present?
      return headers['Authorization'].split(' ').last
    end
      raise(ExceptionHandler::MissingToken, Message.missing_token)
  end
end
```
Define `ExceptionHandler` module
>***./app/auth/exception_handler.rb***
```ruby
module ExceptionHandler
  extend ActiveSupport::Concern

  # Define custom error subclasses - rescue catches `StandardErrors`
  class AuthenticationError < StandardError; end
  class MissingToken < StandardError; end
  class InvalidToken < StandardError; end

  included do
    # Define custom handlers
    rescue_from ActiveRecord::RecordInvalid, with: :four_twenty_two
    rescue_from ExceptionHandler::AuthenticationError, with: :unauthorized_request
    rescue_from ExceptionHandler::MissingToken, with: :four_twenty_two
    rescue_from ExceptionHandler::InvalidToken, with: :four_twenty_two

    rescue_from ActiveRecord::RecordNotFound do |e|
      json_response({ message: e.message }, :not_found)
    end
  end

  private

  # JSON response with message; Status code 422 - unprocessable entity
  def four_twenty_two(e)
    json_response({ message: e.message }, :unprocessable_entity)
  end

  # JSON response with message; Status code 401 - Unauthorized
  def unauthorized_request(e)
    json_response({ message: e.message }, :unauthorized)
  end
end
```

Create singleton `Message` file (in `app/lib` since it’s non-domain-specific)
```sh
touch app/lib/message.rb
```

Define class
>***./app/lib/message.rb***
```ruby 
class Message
  def self.not_found(record = 'record')
    "Sorry, #{record} not found."
  end

  def self.invalid_credentials
    'Invalid credentials'
  end

  def self.invalid_token
    'Invalid token'
  end

  def self.missing_token
    'Missing token'
  end

  def self.unauthorized
    'Unauthorized request'
  end

  def self.account_created
    'Account created successfully'
  end

  def self.account_not_created
    'Account could not be created'
  end

  def self.expired_token
    'Sorry, your token has expired. Please login to continue.'
  end
end
```

Run the auth specs
```sh
bundle exec rspec spec/auth -fd
```

---
## Authenticate Users

Create files
```sh
touch app/auth/authenticate_user.rb && \
touch spec/auth/authenticate_user_spec.rb
```

Define it's specifications.
>***./spec/auth/authenticate_user_spec.rb***
```ruby
require 'rails_helper'

RSpec.describe AuthenticateUser do
  # create test user
  let(:user) { create(:user) }
  # valid request subject
  subject(:valid_auth_obj) { described_class.new(user.email, user.password) }
  # invalid request subject
  subject(:invalid_auth_obj) { described_class.new('foo', 'bar') }

  # Test suite for AuthenticateUser#call
  describe '#call' do
    # return token when valid request
    context 'when valid credentials' do
      it 'returns an auth token' do
        token = valid_auth_obj.call
        expect(token).not_to be_nil
      end
    end

    # raise Authentication Error when invalid request
    context 'when invalid credentials' do
      it 'raises an authentication error' do
        expect { invalid_auth_obj.call }
          .to raise_error(
            ExceptionHandler::AuthenticationError,
            /Invalid credentials/
          )
      end
    end
  end
end
```

The `AuthenticateUser` service accepts a user email and password, checks if they are valid, and then creates a token with the user id as the payload.

Define `AuthenticateUser` class.
>***./app/auth/authenticate_user.rb***
```ruby
class AuthenticateUser
  def initialize(email, password)
    @email = email
    @password = password
  end

  # Service entry point
  def call
    JsonWebToken.encode(user_id: user.id) if user
  end

  private

  attr_reader :email, :password

  # verify user credentials
  def user
    user = User.find_by(email: email)
    return user if user && user.authenticate(password)
    # raise Authentication error if credentials are invalid
    raise(ExceptionHandler::AuthenticationError, Message.invalid_credentials)
  end
end
```

Run the auth specs
```sh
bundle exec rspec spec/auth -fd
```

---
## Authentication Controller
This controller will be responsible for orchestrating the authentication process making use of the auth service

generate the Authentication Controller
```sh
rails g controller Authentication
```

Authentication spec
>***./spec/requests/authentication_spec.rb***
```ruby
require 'rails_helper'

RSpec.describe 'Authentication', type: :request do
  # Authentication test suite
  describe 'POST /auth/login' do
    # create test user
    let!(:user) { create(:user) }
    # set headers for authorization
    let(:headers) { valid_headers.except('Authorization') }
    # set test valid and invalid credentials
    let(:valid_credentials) do
      {
        email: user.email,
        password: user.password
      }.to_json
    end
    let(:invalid_credentials) do
      {
        email: Faker::Internet.email,
        password: Faker::Internet.password
      }.to_json
    end

    # set request.headers to our custon headers
    # before { allow(request).to receive(:headers).and_return(headers) }

    # returns auth token when request is valid
    context 'When request is valid' do
      before { post '/auth/login', params: valid_credentials, headers: headers }

      it 'returns an authentication token' do
        expect(json['auth_token']).not_to be_nil
      end
    end

    # returns failure message when request is invalid
    context 'When request is invalid' do
      before { post '/auth/login', params: invalid_credentials, headers: headers }

      it 'returns a failure message' do
        expect(json['message']).to match(/Invalid credentials/)
      end
    end
  end
end
```
Authentication controller
>***.app/controllers/authentication_controller.rb***
```ruby
class AuthenticationController < ApplicationController
  # return auth token once user is authenticated
  def authenticate
    auth_token =
      AuthenticateUser.new(auth_params[:email], auth_params[:password]).call
    json_response(auth_token: auth_token)
  end

  private

  def auth_params
    params.permit(:email, :password)
  end
end
```

The authentication controller should expose an _/auth/login_ endpoint that accepts user credentials and returns a **JSON** response with the result.

Add routing for authentication action
>***./config/routes.rb***
```ruby
Rails.application.routes.draw do
  # [...]
  post 'auth/login', to: 'authentication#authenticate'
end
```

### User controller
Generate users controller
```sh
rails g controller Users
```

Generate users request spec
```sh
touch spec/requests/users_spec.rb
```

User signup spec
>***./spec/requests/users_spec.rb***
```ruby
require 'rails_helper'

RSpec.describe 'Users API', type: :request do
  let(:user) { build(:user) }
  let(:headers) { valid_headers.except('Authorization') }
  let(:valid_attributes) do
    attributes_for(:user, password_confirmation: user.password)
  end

  # User signup test suite
  describe 'POST /signup' do
    context 'when valid request' do
      before { post '/signup', params: valid_attributes.to_json, headers: headers }

      it 'creates a new user' do
        expect(response).to have_http_status(201)
      end

      it 'returns success message' do
        expect(json['message']).to match(/Account created successfully/)
      end

      it 'returns an authentication token' do
        expect(json['auth_token']).not_to be_nil
      end
    end

    context 'when invalid request' do
      before { post '/signup', params: {}, headers: headers }

      it 'does not create a new user' do
        expect(response).to have_http_status(422)
      end

      it 'returns failure message' do
        expect(json['message'])
          .to match(/Validation failed: Password can't be blank, Name can't be blank, Email can't be blank, Password digest can't be blank/)
      end
    end
  end
end
```

The user controller should expose a _/signup_ endpoint that accepts user information and returns a JSON response with the result.

Add the signup route
>***./config/routes.rb***
```ruby
Rails.application.routes.draw do
  # [...]
  post 'signup', to: 'users#create'
end
```

Define `User` controller
>***./app/controllers/users_controller.rb***
```ruby
class UsersController < ApplicationController
  # POST /signup
  # return authenticated token upon signup
  def create
    user = User.create!(user_params)
    auth_token = AuthenticateUser.new(user.email, user.password).call
    response = { message: Message.account_created, auth_token: auth_token }
    json_response(response, :created)
  end

  private

  def user_params
    params.permit(
      :name,
      :email,
      :password,
      :password_confirmation
    )
  end
end
```

***The users’ controller attempts to create a user and returns a JSON response with the result. We use Active Record’s create! method so that in the event there’s an error, an exception will be raised and handled in the exception handler.***

***One more thing, we’ve wired up the user authentication bit but our API is still open; it does not authorize requests with a token***

***To fix this, we have to make sure that on every request (except authentication) our API checks for a valid token. To achieve this, we’ll implement a callback in the application controller that authenticates every request. Since all controllers inherit from the application controller, it will be propagated to all controllers.***

Create application controller spec
```sh
mkdir spec/controllers && \
touch spec/controllers/application_controller_spec.rb
```
Define controller spec
>***./spec/controllers/application_controller_spec.rb***
```ruby
require "rails_helper"

RSpec.describe ApplicationController, type: :controller do
  # create test user
  let!(:user) { create(:user) }
   # set headers for authorization
  let(:headers) { { 'Authorization' => token_generator(user.id) } }
  let(:invalid_headers) { { 'Authorization' => nil } }

  describe "#authorize_request" do
    context "when auth token is passed" do
      before { allow(request).to receive(:headers).and_return(headers) }

      # private method authorize_request returns current user
      it "sets the current user" do
        expect(subject.instance_eval { authorize_request }).to eq(user)
      end
    end

    context "when auth token is not passed" do
      before do
        allow(request).to receive(:headers).and_return(invalid_headers)
      end

      it "raises MissingToken error" do
        expect { subject.instance_eval { authorize_request } }.
          to raise_error(ExceptionHandler::MissingToken, /Missing token/)
      end
    end
  end
end
```
Define controller
>***./app/controllers/application_controller.rb***
```ruby
class ApplicationController < ActionController::API
  include Response
  include ExceptionHandler

  # called before every action on controllers
  before_action :authorize_request
  attr_reader :current_user

  private

  # Check for valid request token and return user
  def authorize_request
    @current_user = (AuthorizeApiRequest.new(request.headers).call)[:user]
  end
end
```
Update `AuthenticationController` and `UsersController`, adding `skip_before_action`
>***./app/controllers/authentication_controller.rb***
```ruby
class AuthenticationController < ApplicationController
  skip_before_action :authorize_request, only: :authenticate
  # [...]
end
```

>***./app/controllers/users_controller.rb***
```ruby
class UsersController < ApplicationController
  skip_before_action :authorize_request, only: :create
  # [...]
end
```
Update `Todo` spec and controller
>***./spec/requests/todos_spec.rb***
```ruby
require 'rails_helper'

RSpec.describe 'Todos API', type: :request do
  # # initialize test data
  # let!(:todos) { create_list(:todo, 10) }
  # let(:todo_id) { todos.first.id }
  # ________________________________
  # add todos owner
  let(:user) { create(:user) }
  let!(:todos) { create_list(:todo, 10, created_by: user.id) }
  let(:todo_id) { todos.first.id }
  # authorize request
  let(:headers) { valid_headers }

  # Test suite for GET /todos
  describe 'GET /todos' do
    # # make HTTP get request before each example
    # before { get '/todos' }
    # ___________________________
    # update request with headers
    before { get '/todos', params: {}, headers: headers }

    it 'returns todos' do
      # Note `json` is a custom helper to parse JSON responses
      expect(json).not_to be_empty
      expect(json.size).to eq(10)
    end

    it 'returns status code 200' do
      expect(response).to have_http_status(200)
    end
  end

  # Test suite for GET /todos/:id
  describe 'GET /todos/:id' do
    # before { get "/todos/#{todo_id}" }
    # ______________________________________________________________
    before { get "/todos/#{todo_id}", params: {}, headers: headers }

    context 'when the record exists' do
      it 'returns the todo' do
        expect(json).not_to be_empty
        expect(json['id']).to eq(todo_id)
      end

      it 'returns status code 200' do
        expect(response).to have_http_status(200)
      end
    end

    context 'when the record does not exist' do
      let(:todo_id) { 100 }

      it 'returns status code 404' do
        expect(response).to have_http_status(404)
      end

      it 'returns a not found message' do
        expect(response.body).to match(/Couldn't find Todo/)
      end
    end
  end

  # Test suite for POST /todos
  describe 'POST /todos' do
    # # valid payload
    # let(:valid_attributes) { { title: 'Learn Elm', created_by: '1' } }
    # __________________________________________________________________
    let(:valid_attributes) do
      # send json payload
      { title: 'Learn Elm', created_by: user.id.to_s }.to_json
    end

    context 'when the request is valid' do
      # before { post '/todos', params: valid_attributes }
      # __________________________________________________________________
      before { post '/todos', params: valid_attributes, headers: headers }

      it 'creates a todo' do
        expect(json['title']).to eq('Learn Elm')
      end

      it 'returns status code 201' do
        expect(response).to have_http_status(201)
      end
    end

    context 'when the request is invalid' do
      # before { post '/todos', params: { title: 'Foobar' } }
      # _____________________________________________________
      let(:invalid_attributes) { { title: nil }.to_json }
      before { post '/todos', params: invalid_attributes, headers: headers }

      it 'returns status code 422' do
        expect(response).to have_http_status(422)
      end

      it 'returns a validation failure message' do
        # expect(response.body)
        #   .to match(/Validation failed: Created by can't be blank/)
        # ____________________
        expect(json['message'])
          .to match(/Validation failed: Title can't be blank/)
      end
    end
  end

  # Test suite for PUT /todos/:id
  describe 'PUT /todos/:id' do
    # let(:valid_attributes) { { title: 'Shopping' } }
    # ______________________________________________________
    let(:valid_attributes) { { title: 'Shopping' }.to_json }

    context 'when the record exists' do
      # before { put "/todos/#{todo_id}", params: valid_attributes }
      # ____________________________________________________________________________
      before { put "/todos/#{todo_id}", params: valid_attributes, headers: headers }

      it 'updates the record' do
        expect(response.body).to be_empty
      end

      it 'returns status code 204' do
        expect(response).to have_http_status(204)
      end
    end
  end

  # Test suite for DELETE /todos/:id
  describe 'DELETE /todos/:id' do
    # before { delete "/todos/#{todo_id}" }
    # _________________________________________________________________
    before { delete "/todos/#{todo_id}", params: {}, headers: headers }

    it 'returns status code 204' do
      expect(response).to have_http_status(204)
    end
  end
end
```

>***./app/controllers/todos_controller.rb***
```ruby
class TodosController < ApplicationController
  before_action :set_todo, only: %i[show update destroy]

  # GET /todos
  def index
    # @todos = Todo.all
    # json_response(@todos)
    # ______________________
    # get current user todos
    @todos = current_user.todos
    json_response(@todos)
  end

  # POST /todos
  def create
    # @todo = Todo.create!(todo_params)
    # json_response(@todo, :created)
    # ______________________________________
    # create todos belonging to current user
    @todo = current_user.todos.create!(todo_params)
    json_response(@todo, :created)
  end

  # GET /todos/:id
  def show
    json_response(@todo)
  end

  # PUT /todos/:id
  def update
    @todo.update(todo_params)
    head :no_content
  end

  # DELETE /todos/:id
  def destroy
    @todo.destroy
    head :no_content
  end

  private

  def todo_params
    # whitelist params
    # params.permit(:title, :created_by)
    # _____________________________________________________
    # remove `created_by` from list of permitted parameters
    params.permit(:title)
  end

  def set_todo
    @todo = Todo.find(params[:id])
  end
end
```

Update only `Item` spec
>***./spec/requests/items_spec.rb***
```ruby
require 'rails_helper'

RSpec.describe 'Items API' do
  # Initialize the test data
  # let!(:todo) { create(:todo) }
  # let!(:items) { create_list(:item, 20, todo_id: todo.id) }
  # let(:todo_id) { todo.id }
  # let(:id) { items.first.id }
  # ___________________________
  let(:user) { create(:user) }
  let!(:todo) { create(:todo, created_by: user.id) }
  let!(:items) { create_list(:item, 20, todo_id: todo.id) }
  let(:todo_id) { todo.id }
  let(:id) { items.first.id }
  let(:headers) { valid_headers }

  # Test suite for GET /todos/:todo_id/items
  describe 'GET /todos/:todo_id/items' do
    # before { get "/todos/#{todo_id}/items" }
    # ____________________________________________________________________
    before { get "/todos/#{todo_id}/items", params: {}, headers: headers }

    context 'when todo exists' do
      it 'returns status code 200' do
        expect(response).to have_http_status(200)
      end

      it 'returns all todo items' do
        expect(json.size).to eq(20)
      end
    end

    context 'when todo does not exist' do
      let(:todo_id) { 0 }

      it 'returns status code 404' do
        expect(response).to have_http_status(404)
      end

      it 'returns a not found message' do
        expect(response.body).to match(/Couldn't find Todo/)
      end
    end
  end

  # Test suite for GET /todos/:todo_id/items/:id
  describe 'GET /todos/:todo_id/items/:id' do
    # before { get "/todos/#{todo_id}/items/#{id}" }
    # __________________________________________________________________________
    before { get "/todos/#{todo_id}/items/#{id}", params: {}, headers: headers }

    context 'when todo item exists' do
      it 'returns status code 200' do
        expect(response).to have_http_status(200)
      end

      it 'returns the item' do
        expect(json['id']).to eq(id)
      end
    end

    context 'when todo item does not exist' do
      let(:id) { 0 }

      it 'returns status code 404' do
        expect(response).to have_http_status(404)
      end

      it 'returns a not found message' do
        expect(response.body).to match(/Couldn't find Item/)
      end
    end
  end

  # Test suite for PUT /todos/:todo_id/items
  describe 'POST /todos/:todo_id/items' do
    # let(:valid_attributes) { { name: 'Visit Narnia', done: false } }
    # ______________________________________________________________________
    let(:valid_attributes) { { name: 'Visit Narnia', done: false }.to_json }

    context 'when request attributes are valid' do
      # before { post "/todos/#{todo_id}/items", params: valid_attributes }
      # ___________________________________________________________________
      before do
        post "/todos/#{todo_id}/items", params: valid_attributes, headers: headers
      end

      it 'returns status code 201' do
        expect(response).to have_http_status(201)
      end
    end

    context 'when an invalid request' do
      # before { post "/todos/#{todo_id}/items", params: {} }
      # _____________________________________________________________________
      before { post "/todos/#{todo_id}/items", params: {}, headers: headers }

      it 'returns status code 422' do
        expect(response).to have_http_status(422)
      end

      it 'returns a failure message' do
        expect(response.body).to match(/Validation failed: Name can't be blank/)
      end
    end
  end

  # Test suite for PUT /todos/:todo_id/items/:id
  describe 'PUT /todos/:todo_id/items/:id' do
    # let(:valid_attributes) { { name: 'Mozart' } }
    # ___________________________________________________
    let(:valid_attributes) { { name: 'Mozart' }.to_json }

    # before { put "/todos/#{todo_id}/items/#{id}", params: valid_attributes }
    # ________________________________________________________________________________
    before do
      put "/todos/#{todo_id}/items/#{id}", params: valid_attributes, headers: headers
    end

    context 'when item exists' do
      it 'returns status code 204' do
        expect(response).to have_http_status(204)
      end

      it 'updates the item' do
        updated_item = Item.find(id)
        expect(updated_item.name).to match(/Mozart/)
      end
    end

    context 'when the item does not exist' do
      let(:id) { 0 }

      it 'returns status code 404' do
        expect(response).to have_http_status(404)
      end

      it 'returns a not found message' do
        expect(response.body).to match(/Couldn't find Item/)
      end
    end
  end

  # Test suite for DELETE /todos/:id
  describe 'DELETE /todos/:id' do
    # before { delete "/todos/#{todo_id}/items/#{id}" }
    # _____________________________________________________________________________
    before { delete "/todos/#{todo_id}/items/#{id}", params: {}, headers: headers }

    it 'returns status code 204' do
      expect(response).to have_http_status(204)
    end
  end
end
```

Run the specs
```sh
bundle exec rspec
```
---
## Continues In
> ***[Parte_3](https://github.com/chocolatito/todo-api/tree/parte_3)***