# RESTful JSON API With Rails 6 - Ver. 1

Example based on the tutorial:
> [___Build a RESTful JSON API With Rails 5 - Part One___](https://www.digitalocean.com/community/tutorials/build-a-restful-json-api-with-rails-5-part-one)

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
+ [Models and Model tests](#models-and-model-tests)
    - [Generating the models](#generating-the-models)
    - [Model specs](#model-specs)
+ [Controllers](#controllers)
    - [Generating the Controller](#generating-the-controller)
    - [Todo Request specs](#todo-request-specs)
    - [Todo Controller](#todo-controller)
    - [Item Request specs](#item-request-specs)
    - [Item Controller](#item-controller)
+ [Continues In](#continues-in)
---
## Requirements

### Data
- **Todo** : *(title:string, created_by:string)*
- **Item** : *(name:string, done:boolean)*

A **Todo**, has zero or many **Item** records

An **Item**, has only one **Item**

### API Endpoints

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
Generate a new project `todos-api` by running:
```sh
rails new todos-api --api -T
```
#### Dependencies
The gems used

- rspec-rails - Testing framework.
- factorybotrails - A fixtures replacement with a more straightforward syntax.
- shoulda_matchers - Provides RSpec with additional matchers.
- database_cleaner - Cleans the test database to ensure a clean state in each test suite.
- faker - A library for generating fake data.

---
In `Gemfile`:

Add `rspec-rails` to both the `:development` and `:test groups`.

> ___./Gemfile___
```ruby
group :development, :test do
  # [...]
  gem 'rspec-rails'
end
```

Add `factory_bot_rails`, `shoulda_matchers`, `faker` and `database_cleaner` to the `:test group`.
> ___./Gemfile___
```ruby
group :test do
  gem 'database_cleaner', '~> 2.0.1'
  gem 'factory_bot_rails', '~> 4.11.1' # version '~> 5.0' change setups
  gem 'faker', '~> 2.19.0'
  gem 'shoulda-matchers', '~> 4.5.1'  
end
```

Install gems:
```sh
bundle install
 ```

---
### Prepare Test Environment

Initialize the spec directory (where tests will reside)
```sh
rails generate rspec:install
```
Create a factory directory for define the 'model factories'. (the factory bot uses it as the default directory).
```sh
mkdir spec/factories
```

In `spec/rails_helper.rb`
>___./spec/rails_helper.rb___
```ruby
# require database cleaner at the top level
require 'database_cleaner'

# [...]
# configure shoulda matchers to use rspec as the test framework
# and full matcher libraries for rails
Shoulda::Matchers.configure do |config|
  config.integrate do |with|
    with.test_framework :rspec
    with.library :rails
  end
end

RSpec.configure do |config|
  # [...]  
  # add `FactoryBot` methods
  config.include FactoryBot::Syntax::Methods
  config.include RequestSpecHelper, type: :request

  # start by truncating all the tables
  # but then use the faster transaction strategy the rest of the time.
  config.before(:suite) do
    DatabaseCleaner.clean_with(:truncation)
    DatabaseCleaner.strategy = :transaction
  end
  # start the transaction strategy as examples are run
  config.around(:each) do |example|
    DatabaseCleaner.cleaning do
      example.run
    end
  end
  # [...]
end
```

---
## Models and Model tests

### Generating the models

`Todo` model
```sh
rails g model Todo title:string created_by:string
```
`Item` model
```sh
rails g model Item name:string done:boolean todo:references

```

> The generator invokes `active record` and `rspec` to generate the migration, model, and spec respectively.
> `todo:references` will do the following:
>> - Add a `foreign key` column `todo_id` to the `items` table
>> - Setup a `belongs_to` association in the `Item` model
>

Run the migrations.
```sh
rails db:migrate
```

### Model specs
> ___./spec/models/todo_spec.rb___
```ruby
require 'rails_helper'

# Test suite for the Todo model
RSpec.describe Todo, type: :model do
  # Association test
  # ensure Todo model has a 1:m relationship with the Item model
  it { should have_many(:items).dependent(:destroy) }
  # Validation tests
  # ensure columns title and created_by are present before saving
  it { should validate_presence_of(:title) }
  it { should validate_presence_of(:created_by) }
end
```
>___./spec/models/item_spec.rb___
```ruby
require 'rails_helper'

# Test suite for the Item model
RSpec.describe Item, type: :model do
  # Association test
  # ensure an item record belongs to a single todo record
  it { should belong_to(:todo) }
  # Validation test
  # ensure column name is present before saving
  it { should validate_presence_of(:name) }
end
```
>___./app/models/todo.rb___
```ruby
class Todo < ApplicationRecord
  # model association
  has_many :items, dependent: :destroy

  # validations
  validates_presence_of :title, :created_by
end
```
>___./app/models/item.rb___
```ruby
class Item < ApplicationRecord
  # model association
  belongs_to :todo

  # validation
  validates_presence_of :name
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
## Controllers


### Generating the Controller 

`Todos` and `Items` controllers 
```sh
rails g controller Todos && \
rails g controller Items
```

### Todo Request specs
Generating controllers by default generates controller specs.
However, However, it is preferable to use request specifications.
>According to RSpec, the official recommendation of the Rails team and the RSpec core team is to write request specs instead.

If not exist, Add a `requests` folder to the `spec` directory
```sh
mkdir spec/requests
```
The corresponding spec files.
```sh
touch spec/requests/{todos_spec.rb,items_spec.rb}
```
Add the model factories which will provide the test data.
```sh
touch spec/factories/{todos.rb,items.rb}
```
Define the factories.
>___./spec/factories/todos.rb___
```ruby
FactoryBot.define do
  factory :todo do
    title { Faker::Lorem.word }
    created_by { Faker::Number.number(10) }
  end
end
```
>___./spec/factories/items.rb___
```ruby
FactoryBot.define do
  factory :item do
    name { Faker::Movies::Lebowski.character }
    done false
    todo_id nil
  end
end
```
By wrapping Faker methods in a block, we ensure that Faker generates dynamic data every time the factory is invoked.
This way, we always have unique data.

> ___./spec/requests/todos_spec.rb___
```ruby
require 'rails_helper'

RSpec.describe 'Todos API', type: :request do
  # initialize test data
  let!(:todos) { create_list(:todo, 10) }
  let(:todo_id) { todos.first.id }

  # Test suite for GET /todos
  describe 'GET /todos' do
    # make HTTP get request before each example
    before { get '/todos' }

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
    before { get "/todos/#{todo_id}" }

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
    # valid payload
    let(:valid_attributes) { { title: 'Learn Elm', created_by: '1' } }

    context 'when the request is valid' do
      before { post '/todos', params: valid_attributes }

      it 'creates a todo' do
        expect(json['title']).to eq('Learn Elm')
      end

      it 'returns status code 201' do
        expect(response).to have_http_status(201)
      end
    end

    context 'when the request is invalid' do
      before { post '/todos', params: { title: 'Foobar' } }

      it 'returns status code 422' do
        expect(response).to have_http_status(422)
      end

      it 'returns a validation failure message' do
        expect(response.body)
          .to match(/Validation failed: Created by can't be blank/)
      end
    end
  end

  # Test suite for PUT /todos/:id
  describe 'PUT /todos/:id' do
    let(:valid_attributes) { { title: 'Shopping' } }

    context 'when the record exists' do
      before { put "/todos/#{todo_id}", params: valid_attributes }

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
    before { delete "/todos/#{todo_id}" }

    it 'returns status code 204' do
      expect(response).to have_http_status(204)
    end
  end
end
```
`json` in a **custom helper method** which parses the JSON response to a Ruby Hash which is easier to work with in the tests.
Add the directory and file:
```sh
mkdir spec/support && \
touch spec/support/request_spec_helper.rb
```
> ___./spec/support/request_spec_helper___
```ruby
module RequestSpecHelper
  # Parse JSON response to ruby hash
  def json
    JSON.parse(response.body)
  end
end
```
The support directory **is not autoloaded by default**. To enable this
- In _rails_helper.rb_, comment out the support directory auto-loading
- Include it as shared module for all request specs in the RSpec configuration block.
>___./spec/rails_helper.rb___
```ruby
# [...]
Dir[Rails.root.join('spec/support/**/*.rb')].each { |f| require f }
# [...]
RSpec.configuration do |config|
  # [...]
    config.include RequestSpecHelper, type: :request
  # [...]
end
```

### Todo Controller
Define the routes
> ___./config/routes.rb___
```ruby
Rails.application.routes.draw do
  resources :todos do
    resources :items
  end
end
```
To view the routes:
```sh
rails routes
```
Define the controller methods
>___./app/controllers/todos_controller.rb___
```sh
class TodosController < ApplicationController
  before_action :set_todo, only: %i[show update destroy]

  # GET /todos
  def index
    @todos = Todo.all
    json_response(@todos)
  end

  # POST /todos
  def create
    @todo = Todo.create!(todo_params)
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
    params.permit(:title, :created_by)
  end

  def set_todo
    @todo = Todo.find(params[:id])
  end
end
```
The helpers
- `json_response` which responds with JSON and an HTTP status code (200 by default).

Create *response.rb* file in concerns folder
```sh
touch app/controllers/concerns/response.rb
```
Define this method
>___./app/controllers/concerns/response.rb___
```ruby
module Response
  def json_response(object, status = :ok)
    render json: object, status: status
  end
end
```

- `set_todo` - callback method to find a `todo` record by `id`. In the case where the record does not exist, ActiveRecord will throw an exception `ActiveRecord::RecordNotFound`. We’ll rescue from this exception and return a `404` message.

Create *exception_handler.rb* file in concerns folder
```sh
touch app/controllers/concerns/exception_handler.rb
```
Define this method
>___./app/controllers/concerns/exception_handler.rb___
```ruby
module ExceptionHandler
  # provides the more graceful `included` method
  extend ActiveSupport::Concern

  included do
    rescue_from ActiveRecord::RecordNotFound do |e|
      json_response({ message: e.message }, :not_found)
    end

    rescue_from ActiveRecord::RecordInvalid do |e|
      json_response({ message: e.message }, :unprocessable_entity)
    end
  end
end
```
Include the modules in the application controller.
>___./app/controllers/application_controller.rb___
```ruby
class ApplicationController < ActionController::API
  include Response
  include ExceptionHandler
end
```
Run the tests
```sh
bundle exec rspec
```
Or, only requests
```sh
bbundle exec rspec ./spec/requests/
```

### Item Request specs

>___./spec/requests/items_spec.rb___
```ruby
require 'rails_helper'

RSpec.describe 'Items API' do
  # Initialize the test data
  let!(:todo) { create(:todo) }
  let!(:items) { create_list(:item, 20, todo_id: todo.id) }
  let(:todo_id) { todo.id }
  let(:id) { items.first.id }

  # Test suite for GET /todos/:todo_id/items
  describe 'GET /todos/:todo_id/items' do
    before { get "/todos/#{todo_id}/items" }

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
    before { get "/todos/#{todo_id}/items/#{id}" }

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
    let(:valid_attributes) { { name: 'Visit Narnia', done: false } }

    context 'when request attributes are valid' do
      before { post "/todos/#{todo_id}/items", params: valid_attributes }

      it 'returns status code 201' do
        expect(response).to have_http_status(201)
      end
    end

    context 'when an invalid request' do
      before { post "/todos/#{todo_id}/items", params: {} }

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
    let(:valid_attributes) { { name: 'Mozart' } }

    before { put "/todos/#{todo_id}/items/#{id}", params: valid_attributes }

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
    before { delete "/todos/#{todo_id}/items/#{id}" }

    it 'returns status code 204' do
      expect(response).to have_http_status(204)
    end
  end
end
```

### Item Controller
>___./app/controllers/items_controller.rb___
```ruby
class ItemsController < ApplicationController
  before_action :set_todo
  before_action :set_todo_item, only: %i[show update destroy]

  # GET /todos/:todo_id/items
  def index
    json_response(@todo.items)
  end

  # GET /todos/:todo_id/items/:id
  def show
    json_response(@item)
  end

  # POST /todos/:todo_id/items
  def create
    @todo.items.create!(item_params)
    json_response(@todo, :created)
  end

  # PUT /todos/:todo_id/items/:id
  def update
    @item.update(item_params)
    head :no_content
  end

  # DELETE /todos/:todo_id/items/:id
  def destroy
    @item.destroy
    head :no_content
  end

  private

  def item_params
    params.permit(:name, :done)
  end

  def set_todo
    @todo = Todo.find(params[:todo_id])
  end

  def set_todo_item
    @item = @todo.items.find_by!(id: params[:id]) if @todo
  end
end
```
Or, only requests
```sh
bbundle exec rspec ./spec/requests/
```
---

## Continues In
> ***[Parte_2](https://github.com/chocolatito/todo-api/tree/parte_2)***